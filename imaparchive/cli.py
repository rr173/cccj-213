"""Command-line entry points.

Environment variables consumed (none are ever written to disk):
    IMAP_HOST, IMAP_PORT, IMAP_USER, IMAP_PASSWORD, IMAP_MAILBOX,
    IMAP_TLS (ssl|starttls|none), IMAP_TLS_VERIFY,
    IMAPARCHIVE_DATA, IMAPARCHIVE_CHUNK_SIZE, IMAPARCHIVE_TIMEOUT
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .archive import AssemblyError, Layout, export
from .collector import Collector, verify_integrity
from .config import Config, ConfigError
from .protocol import AuthError, ConnectionLost, ImapError


def _layout(config: Config) -> Layout:
    layout = Layout(config.data_dir)
    layout.root.mkdir(parents=True, exist_ok=True)
    return layout


def _emit(payload: dict) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def cmd_collect(args: argparse.Namespace) -> int:
    config = Config.from_env()
    layout = _layout(config)
    store = layout.store()
    try:
        collector = Collector(config, store, layout)
        result = collector.run()
    finally:
        store.close()
    _emit({"action": "collect", **result.as_dict()})
    return 0 if result.status == "complete" else 2


def cmd_check(args: argparse.Namespace) -> int:
    config = Config.offline_from_env()
    layout = _layout(config)
    store = layout.store()
    try:
        generations = [
            {
                "generation_id": int(row["id"]),
                "mailbox": row["mailbox"],
                "uidvalidity": int(row["uidvalidity"]),
                "opened_at": row["opened_at"],
                "last_seen_uidnext": row["last_seen_uidnext"],
                "last_seen_highestmodseq": row["last_seen_highestmodseq"],
                "complete": int(row["complete_count"]),
                "known": int(row["known_count"]),
            }
            for row in store.list_generations(config.mailbox)
        ]
        rounds = [
            {
                "round_id": int(row["id"]),
                "generation_id": int(row["generation_id"]),
                "uidvalidity": int(row["uidvalidity"]),
                "status": row["status"],
                "uidnext_at_round": int(row["uidnext_at_round"]),
                "uid_next_progress": int(row["uid_next_progress"]),
                "condstore": bool(row["condstore"]),
                "qresync": bool(row["qresync"]),
                "full_inventory": bool(row["full_inventory"]),
                "baseline": row["highestmodseq_baseline"],
                "highestmodseq_at_end": row["highestmodseq_at_end"],
                "error": row["error"],
            }
            for row in store.rounds()
            if row["mailbox"] == config.mailbox
        ]
        if args.uid is not None:
            generation = store.conn.execute(
                "SELECT g.id FROM generations g JOIN mailboxes m ON m.id=g.mailbox_id "
                "WHERE m.name=? AND g.uidvalidity=?",
                (config.mailbox, args.uidvalidity),
            ).fetchone() if args.uidvalidity is not None else None
            if generation is None:
                _emit({"action": "check", "error": "generation not found"})
                return 2
            message = store.message(int(generation["id"]), args.uid)
            if message is None:
                _emit({"action": "check", "error": "uid not archived"})
                return 2
            flags = store.flags(int(message["id"]))
            parts = [
                {
                    "origin": int(p["origin"]),
                    "length": int(p["length"]),
                    "sha256": p["sha256"],
                }
                for p in store.parts(int(message["id"]))
            ]
            _emit(
                {
                    "action": "check",
                    "mailbox": config.mailbox,
                    "uidvalidity": args.uidvalidity,
                    "uid": args.uid,
                    "complete": bool(message["complete"]),
                    "status": message["status"],
                    "body_length": message["body_length"],
                    "body_sha256": message["body_sha256"],
                    "body_path": message["body_path"],
                    "message_id": message["message_id"],
                    "parts": parts,
                    "flags": json.loads(flags["flags_json"]) if flags else None,
                    "flags_source": flags["source"] if flags else None,
                    "flags_observed_at": flags["observed_at"] if flags else None,
                    "conflict_reason": message["conflict_reason"],
                }
            )
            return 0
        _emit(
            {
                "action": "check",
                "mailbox": config.mailbox,
                "generations": generations,
                "rounds": rounds,
                "integrity": verify_integrity(store),
            }
        )
    finally:
        store.close()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    config = Config.offline_from_env()
    layout = _layout(config)
    store = layout.store()
    try:
        result = export(store, Path(args.out), copy_bodies=not args.manifest_only)
    except AssemblyError as exc:
        _emit({"action": "export", "error": str(exc)})
        return 2
    finally:
        store.close()
    _emit({"action": "export", **result})
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    config = Config.offline_from_env()
    layout = _layout(config)
    store = layout.store()
    try:
        problems = verify_integrity(store)
    finally:
        store.close()
    _emit({"action": "verify", "problems": problems, "ok": not problems})
    return 0 if not problems else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="imaparchive",
        description="Read-only, resumable IMAP archival collector (RFC 3501 bytes)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="run one round (resumes an open round)")
    collect.set_defaults(func=cmd_collect)

    resume = sub.add_parser("resume", help="continue an unfinished round")
    resume.set_defaults(func=cmd_collect)

    check = sub.add_parser("check", help="inspect generations, rounds and a UID")
    check.add_argument("--uidvalidity", type=int, default=None)
    check.add_argument("--uid", type=int, default=None)
    check.set_defaults(func=cmd_check)

    export_cmd = sub.add_parser("export", help="offline export of complete messages")
    export_cmd.add_argument("--out", required=True)
    export_cmd.add_argument(
        "--manifest-only", action="store_true", help="do not copy bodies"
    )
    export_cmd.set_defaults(func=cmd_export)

    verify = sub.add_parser("verify", help="check progress/body invariants offline")
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 64
    except AuthError as exc:
        print(f"authentication failed: {exc}", file=sys.stderr)
        return 77
    except ConnectionLost as exc:
        print(f"connection lost: {exc}", file=sys.stderr)
        return 75
    except ImapError as exc:
        print(f"imap error: {exc}", file=sys.stderr)
        return 76
