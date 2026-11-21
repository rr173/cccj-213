"""Shared fixtures: a real loopback IMAP server and an archive under tmp_path."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from imaparchive.archive import Layout  # noqa: E402
from imaparchive.collector import Collector  # noqa: E402
from imaparchive.config import Config  # noqa: E402


def make_message(
    n: int,
    *,
    message_id: str | None = None,
    body: bytes | None = None,
    body_lines: int = 20,
) -> bytes:
    if body is None:
        body = (
            "".join(
                f"line {i:03d} of message {n}: " + "x" * 40 + "\r\n"
                for i in range(body_lines)
            )
        ).encode("ascii")
    mid = message_id if message_id is not None else f"<msg-{n}@example.test>"
    header = (
        f"From: sender{n}@example.test\r\n"
        f"To: archive@example.test\r\n"
        f"Subject: message {n}\r\n"
        f"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
        f"Message-ID: {mid}\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
    ).encode("ascii")
    return header + body


@dataclass
class Harness:
    root: Path
    config: Config
    layout: Layout

    def store(self):
        return self.layout.store()

    def run(self, *, expect_error: bool = False):
        """Run one round on a fresh SQLite connection (like a new process)."""
        store = self.layout.store()
        try:
            result = Collector(self.config, store, self.layout).run()
        finally:
            store.close()
        return result

    def catalog(self) -> dict:
        """Catalogue read back from a fresh connection, not from memory."""
        store = self.layout.store()
        try:
            generations = [
                int(row["uidvalidity"])
                for row in store.conn.execute(
                    "SELECT uidvalidity FROM generations ORDER BY uidvalidity"
                )
            ]
            messages = [
                {
                    "uidvalidity": int(row["uidvalidity"]),
                    "uid": int(row["uid"]),
                    "complete": bool(row["complete"]),
                    "sha256": row["body_sha256"],
                    "length": row["body_length"],
                    "path": row["body_path"],
                    "message_id": row["message_id"],
                    "status": row["status"],
                }
                for row in store.conn.execute(
                    "SELECT m.*, g.uidvalidity FROM messages m "
                    "JOIN generations g ON g.id=m.generation_id "
                    "ORDER BY g.uidvalidity, m.uid"
                )
            ]
            rounds = [
                {
                    "id": int(row["id"]),
                    "status": row["status"],
                    "uidnext_at_round": int(row["uidnext_at_round"]),
                    "uid_next_progress": int(row["uid_next_progress"]),
                    "full_inventory": bool(row["full_inventory"]),
                    "condstore": bool(row["condstore"]),
                    "qresync": bool(row["qresync"]),
                    "baseline": row["highestmodseq_baseline"],
                    "error": row["error"],
                }
                for row in store.conn.execute("SELECT * FROM rounds ORDER BY id")
            ]
            inventory = {}
            for row in store.conn.execute(
                "SELECT i.round_id, i.uid, i.state, i.evidence FROM inventory i "
                "ORDER BY i.round_id, i.uid"
            ):
                inventory.setdefault(int(row["round_id"]), {})[int(row["uid"])] = (
                    row["state"],
                    row["evidence"],
                )
            events = [
                {
                    "round_id": int(row["round_id"]),
                    "seq": int(row["seq"]),
                    "uid": row["uid"],
                    "kind": row["kind"],
                    "detail": row["detail"],
                }
                for row in store.conn.execute(
                    "SELECT * FROM round_events ORDER BY round_id, seq"
                )
            ]
            expunged = {
                int(row["uid"]): row["reason"]
                for row in store.conn.execute("SELECT uid, reason FROM expunged")
            }
            flags = {
                int(row["uid"]): row["flags_json"]
                for row in store.conn.execute(
                    "SELECT m.uid, f.flags_json FROM flags f "
                    "JOIN messages m ON m.id=f.message_id"
                )
            }
        finally:
            store.close()
        return {
            "generations": generations,
            "messages": messages,
            "rounds": rounds,
            "inventory": inventory,
            "events": events,
            "expunged": expunged,
            "flags": flags,
        }

    def body(self, uidvalidity: int, uid: int) -> bytes:
        return self.layout.message_file("INBOX", uidvalidity, uid).read_bytes()

    def body_path(self, uidvalidity: int, uid: int) -> Path:
        return self.layout.message_file("INBOX", uidvalidity, uid)

    def message_files(self, uidvalidity: int) -> list[str]:
        directory = self.layout.messages_dir("INBOX", uidvalidity)
        if not directory.is_dir():
            return []
        return sorted(p.name for p in directory.iterdir())

    def part_files(self, uidvalidity: int) -> list[str]:
        directory = self.layout.parts_dir("INBOX", uidvalidity)
        if not directory.is_dir():
            return []
        return sorted(p.name for p in directory.iterdir())
