"""On-disk layout, message assembly and offline export."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .store import Store

_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")
_MESSAGE_ID_LINE = re.compile(rb"^message-id[ \t]*:[ \t]*(.*)$", re.I)
_HEADER_LIMIT = 1024 * 1024


class AssemblyError(Exception):
    pass


class ConflictError(AssemblyError):
    pass


def safe_component(value: str) -> str:
    if _SAFE.match(value) and value not in {".", ".."}:
        return value
    return "".join(
        ch if (ch.isascii() and (ch.isalnum() or ch in "._-")) else f"%{ord(ch):02X}"
        for ch in value
    )


@dataclass(frozen=True)
class Layout:
    root: Path

    @property
    def db_path(self) -> Path:
        return self.root / "catalogue.sqlite3"

    @property
    def spool(self) -> Path:
        return self.root / "spool"

    def generation_dir(self, mailbox: str, uidvalidity: int) -> Path:
        return self.root / "generations" / safe_component(mailbox) / str(uidvalidity)

    def messages_dir(self, mailbox: str, uidvalidity: int) -> Path:
        return self.generation_dir(mailbox, uidvalidity) / "messages"

    def parts_dir(self, mailbox: str, uidvalidity: int) -> Path:
        return self.generation_dir(mailbox, uidvalidity) / "parts"

    def message_file(self, mailbox: str, uidvalidity: int, uid: int) -> Path:
        return self.messages_dir(mailbox, uidvalidity) / f"{uid}.eml"

    def part_file(self, mailbox: str, uidvalidity: int, uid: int, origin: int) -> Path:
        return self.parts_dir(mailbox, uidvalidity) / f"{uid}.{origin}.part"

    def ensure_generation(self, mailbox: str, uidvalidity: int) -> None:
        self.messages_dir(mailbox, uidvalidity).mkdir(parents=True, exist_ok=True)
        self.parts_dir(mailbox, uidvalidity).mkdir(parents=True, exist_ok=True)
        self.spool.mkdir(parents=True, exist_ok=True)

    def store(self) -> Store:
        return Store(self.db_path)


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def extract_message_id(header: bytes) -> str | None:
    """Return the unfolded Message-ID value.  Catalogue attribute only."""
    end = header.find(b"\r\n\r\n")
    if end < 0:
        end = header.find(b"\n\n")
    if end >= 0:
        header = header[:end]
    lines = header.splitlines()
    for index, line in enumerate(lines):
        match = _MESSAGE_ID_LINE.match(line)
        if not match:
            continue
        value = match.group(1).strip()
        j = index + 1
        while j < len(lines) and lines[j][:1] in (b" ", b"\t"):
            value += b" " + lines[j].strip()
            j += 1
        return value.decode("utf-8", "replace").strip()
    return None


def read_prefix(path: Path, limit: int = _HEADER_LIMIT) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(limit)


def assemble_message(
    store: Store,
    layout: Layout,
    mailbox: str,
    uidvalidity: int,
    uid: int,
    expected_size: int | None,
) -> dict:
    """Assemble verified parts into the published ``.eml``.

    Parts are re-hashed while streaming into a temporary sibling; the rename
    happens only after fsync.  A crash can therefore never leave a truncated
    file at the published path.  An already published body is never replaced.
    """
    generation = store.conn.execute(
        "SELECT g.id FROM generations g JOIN mailboxes m ON m.id=g.mailbox_id "
        "WHERE m.name=? AND g.uidvalidity=?",
        (mailbox, uidvalidity),
    ).fetchone()
    if generation is None:
        raise AssemblyError(f"unknown generation {mailbox}/{uidvalidity}")
    message = store.message(int(generation["id"]), uid)
    if message is None:
        raise AssemblyError(f"no catalogue row for UID {uid}")
    if message["complete"]:
        return {
            "status": "already_complete",
            "sha256": message["body_sha256"],
            "length": message["body_length"],
            "path": message["body_path"],
        }

    parts = store.parts(int(message["id"]))
    if not parts:
        raise AssemblyError(f"UID {uid}: no verified parts")
    final_path = layout.message_file(mailbox, uidvalidity, uid)
    final_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = final_path.with_name(f".{uid}.eml.tmp-{os.getpid()}")
    total = 0
    hasher = hashlib.sha256()
    try:
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "wb") as out:
            for part in parts:
                origin = int(part["origin"])
                if origin != total:
                    raise AssemblyError(
                        f"UID {uid}: parts do not cover contiguously at {total} "
                        f"(next origin {origin})"
                    )
                path = Path(part["path"])
                if not path.is_file():
                    raise AssemblyError(f"UID {uid}: part file missing: {path}")
                h = hashlib.sha256()
                written = 0
                with open(path, "rb") as fh:
                    while True:
                        chunk = fh.read(1024 * 1024)
                        if not chunk:
                            break
                        h.update(chunk)
                        hasher.update(chunk)
                        out.write(chunk)
                        written += len(chunk)
                if written != int(part["length"]):
                    raise AssemblyError(f"UID {uid}: part {origin} changed length on disk")
                if h.hexdigest() != part["sha256"]:
                    raise AssemblyError(f"UID {uid}: part {origin} failed hash verification")
                total += written
            out.flush()
            os.fsync(out.fileno())
        if expected_size is not None and total != expected_size:
            raise AssemblyError(
                f"UID {uid}: assembled {total} bytes, expected {expected_size}"
            )
        digest = hasher.hexdigest()
        if final_path.exists():
            old_sha, old_len = sha256_file(final_path)
            if old_sha == digest and old_len == total:
                temp_path.unlink(missing_ok=True)
            else:
                raise ConflictError(
                    f"UID {uid}: published body exists with different bytes; "
                    "refusing to replace it"
                )
        else:
            os.replace(temp_path, final_path)
    except BaseException:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise

    message_id_header = extract_message_id(read_prefix(final_path))
    store.mark_complete(message["id"], digest, total, str(final_path), message_id_header)
    return {
        "status": "complete",
        "sha256": digest,
        "length": total,
        "path": str(final_path),
        "message_id": message_id_header,
    }


def iter_complete(store: Store) -> list[sqlite3.Row]:
    return store.conn.execute(
        "SELECT m.*, g.uidvalidity, mb.name AS mailbox FROM messages m "
        "JOIN generations g ON g.id=m.generation_id "
        "JOIN mailboxes mb ON mb.id=g.mailbox_id "
        "WHERE m.complete=1 ORDER BY mb.name, g.uidvalidity, m.uid"
    ).fetchall()


def export(store: Store, out_dir: Path, *, copy_bodies: bool = True) -> dict:
    """Export complete messages offline; performs no network I/O."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    copied = 0
    for row in iter_complete(store):
        mailbox = row["mailbox"]
        uidvalidity = int(row["uidvalidity"])
        uid = int(row["uid"])
        src = Path(row["body_path"])
        if not src.is_file():
            raise AssemblyError(f"catalogue says complete but file is missing: {src}")
        digest, length = sha256_file(src)
        if digest != row["body_sha256"] or length != int(row["body_length"]):
            raise AssemblyError(f"body verification failed for {src}")
        target_dir = out_dir / safe_component(mailbox) / str(uidvalidity) / "messages"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / f"{uid}.eml"
        if copy_bodies:
            tmp = target.with_name(f".{uid}.eml.tmp-{os.getpid()}")
            shutil.copyfile(src, tmp)
            os.replace(tmp, target)
            copied += 1
        flag_row = store.flags(int(row["id"]))
        records.append(
            {
                "mailbox": mailbox,
                "uidvalidity": uidvalidity,
                "uid": uid,
                "path": str(target if copy_bodies else src),
                "sha256": digest,
                "length": length,
                "message_id": row["message_id"],
                "flags": json.loads(flag_row["flags_json"]) if flag_row else None,
                "flags_modseq": (
                    int(flag_row["modseq"])
                    if flag_row and flag_row["modseq"] is not None
                    else None
                ),
                "flags_source": flag_row["source"] if flag_row else None,
                "flags_observed_at": (
                    float(flag_row["observed_at"]) if flag_row else None
                ),
                "generation_id": int(row["generation_id"]),
            }
        )
    manifest_path = out_dir / "manifest.jsonl"
    with open(manifest_path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return {
        "exported": len(records),
        "copied": copied,
        "out_dir": str(out_dir),
        "manifest": str(manifest_path),
    }
