#!/usr/bin/env python3
"""End-to-end bounded-memory trial against the scripted IMAP test server.

Generates several large messages at runtime (never committed), collects them
through a real loopback TCP connection, reopens the archive to prove no
re-fetch, and exports offline.  Prints a small JSON report including peak
tracemalloc usage.

    python tools/large_trial.py --count 3 --mib 4
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from imap_testserver import ImapServer, State  # noqa: E402
from make_large_messages import build_message  # noqa: E402

from imaparchive.archive import Layout, export  # noqa: E402
from imaparchive.collector import Collector, verify_integrity  # noqa: E402
from imaparchive.config import Config  # noqa: E402


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--mib", type=int, default=4)
    parser.add_argument("--chunk", type=int, default=128 * 1024)
    args = parser.parse_args(argv)

    state = State()
    expected = []
    size = args.mib * 1024 * 1024
    for index in range(1, args.count + 1):
        data = build_message(index, size)
        state.add(data, uid=index)
        expected.append(
            {"uid": index, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        )
        del data
    state.uidnext = args.count + 1

    server = ImapServer(state).start()
    workdir = Path(tempfile.mkdtemp(prefix="imaparchive-trial-"))
    config = Config(
        host=server.host,
        port=server.port,
        user=state.user,
        password=state.password,
        mailbox="INBOX",
        tls="none",
        data_dir=workdir / "archive",
        chunk_size=args.chunk,
        timeout=30.0,
        verify_tls=False,
    )
    layout = Layout(config.data_dir)
    layout.root.mkdir(parents=True, exist_ok=True)
    report: dict = {"archive": str(layout.root)}

    try:
        tracemalloc.start()
        store = layout.store()
        try:
            first = Collector(config, store, layout).run()
        finally:
            store.close()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        report["first_round"] = {"status": first.status, "complete": first.complete}
        report["peak_bytes"] = peak
        report["total_mail_bytes"] = sum(e["length"] for e in expected)

        store = layout.store()
        try:
            second = Collector(config, store, layout).run()
            problems = verify_integrity(store)
            out = workdir / "export"
            summary = export(store, out)
        finally:
            store.close()
        body_fetches = [e for e in state.log if e["kind"] == "fetch_body"]
        report["second_round"] = {
            "status": second.status,
            "present": second.present,
            "body_chunk_fetches_total": len(body_fetches),
            "chunks_needed_for_one_pass": sum(
                (e["length"] + args.chunk - 1) // args.chunk for e in expected
            ),
        }
        report["integrity_problems"] = problems
        report["export"] = summary

        verified = []
        for entry in expected:
            path = layout.message_file("INBOX", state.uidvalidity, entry["uid"])
            digest, length = sha256_file(path)
            exported = out / "INBOX" / str(state.uidvalidity) / "messages" / f"{entry['uid']}.eml"
            export_digest, export_length = sha256_file(exported)
            verified.append(
                {
                    "uid": entry["uid"],
                    "archive_ok": digest == entry["sha256"] and length == entry["length"],
                    "export_ok": (
                        export_digest == entry["sha256"]
                        and export_length == entry["length"]
                    ),
                }
            )
        report["verified"] = verified
        print(json.dumps(report, indent=2, sort_keys=True))
        ok = (
            not problems
            and first.status == "complete"
            and all(v["archive_ok"] and v["export_ok"] for v in verified)
        )
        return 0 if ok else 1
    finally:
        server.stop()


if __name__ == "__main__":
    raise SystemExit(main())
