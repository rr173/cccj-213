"""Runtime-generated large-message trial: bounded memory, reopen, offline export.

Large bodies are generated at test time into a temporary directory.  Nothing
large is committed to the repository.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tracemalloc
from dataclasses import replace
from pathlib import Path

from support import Harness, make_message

from imaparchive.archive import export
from imaparchive.collector import verify_integrity

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "make_large_messages.py"


def generate(tmp_path: Path, count: int, size: int) -> list[dict]:
    out = tmp_path / "large"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(TOOL),
            "--out",
            str(out),
            "--count",
            str(count),
            "--bytes",
            str(size),
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=str(tmp_path),
    )
    return json.loads(result.stdout)


def stream_sha(path: Path) -> tuple[str, int]:
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


def test_large_messages_bounded_memory_reopen_export(state, harness, tmp_path):
    spec = generate(tmp_path, count=3, size=1024 * 1024)
    for entry in spec:
        state.add(Path(entry["path"]).read_bytes(), uid=entry["uid"])
    state.uidnext = len(spec) + 1

    # Use a realistic chunk size so the trial exercises many chunk boundaries
    # without degenerating into a round-trip benchmark.
    big = Harness(
        root=harness.root,
        config=replace(harness.config, chunk_size=128 * 1024),
        layout=harness.layout,
    )

    tracemalloc.start()
    result = big.run()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert result.status == "complete"
    total = sum(entry["length"] for entry in spec)
    assert total > 3 * 1024 * 1024
    # Bounded memory: no whole mailbox and no whole message is held at once.
    assert peak < 6 * 1024 * 1024, f"peak {peak} bytes for {total} bytes of mail"

    for entry in spec:
        archived = big.body_path(1000, entry["uid"])
        digest, length = stream_sha(archived)
        assert digest == entry["sha256"]
        assert length == entry["length"]

    # Reopening the archive must not duplicate logical messages or refetch.
    before = big.catalog()
    again = big.run()
    assert again.status == "complete"
    after = big.catalog()
    assert [m["sha256"] for m in before["messages"]] == [
        m["sha256"] for m in after["messages"]
    ]
    assert len(after["messages"]) == len(spec)
    assert again.present == sorted(entry["uid"] for entry in spec)
    # A second run over unchanged mail re-downloads nothing.
    assert again.round_id != result.round_id

    # Offline export: no server is contacted.
    out = tmp_path / "exported"
    store = big.store()
    try:
        summary = export(store, out)
        assert verify_integrity(store) == []
    finally:
        store.close()
    assert summary["exported"] == len(spec)
    manifest = [
        json.loads(line) for line in (out / "manifest.jsonl").read_text().splitlines()
    ]
    assert len(manifest) == len(spec)
    for entry in spec:
        matches = [r for r in manifest if r["uid"] == entry["uid"]]
        assert len(matches) == 1
        digest, length = stream_sha(Path(matches[0]["path"]))
        assert digest == entry["sha256"]
        assert length == entry["length"]


def test_message_larger_than_chunk_is_not_held_in_memory(state, harness):
    body = make_message(1, body=b"y" * (256 * 1024))
    state.add(body, uid=1)
    state.uidnext = 2
    chunked = Harness(
        root=harness.root,
        config=replace(harness.config, chunk_size=4096),
        layout=harness.layout,
    )
    result = chunked.run()  # 64 chunks for one message
    assert result.status == "complete"
    digest, length = stream_sha(chunked.body_path(1000, 1))
    assert digest == hashlib.sha256(body).hexdigest()
    assert length == len(body)
