"""SQLite catalogue for the collector.

The catalogue contains no credentials.  Files are referenced by absolute path
inside the archive root; partial spool files are never referenced here.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS generations (
    id INTEGER PRIMARY KEY,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
    uidvalidity INTEGER NOT NULL,
    opened_at REAL NOT NULL,
    last_seen_uidnext INTEGER,
    last_seen_highestmodseq INTEGER,
    UNIQUE (mailbox_id, uidvalidity)
);

CREATE TABLE IF NOT EXISTS rounds (
    id INTEGER PRIMARY KEY,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
    generation_id INTEGER NOT NULL REFERENCES generations(id),
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL,
    uidnext_at_round INTEGER NOT NULL,
    uid_next_progress INTEGER NOT NULL DEFAULT 1,
    condstore INTEGER NOT NULL DEFAULT 0,
    qresync INTEGER NOT NULL DEFAULT 0,
    highestmodseq_baseline INTEGER,
    highestmodseq_at_end INTEGER,
    full_inventory INTEGER NOT NULL DEFAULT 1,
    inventory_done INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE INDEX IF NOT EXISTS rounds_generation ON rounds(generation_id, status);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    generation_id INTEGER NOT NULL REFERENCES generations(id),
    uid INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'known',
    expected_size INTEGER,
    body_digest_pinned INTEGER NOT NULL DEFAULT 0,
    complete INTEGER NOT NULL DEFAULT 0,
    body_sha256 TEXT,
    body_length INTEGER,
    body_path TEXT,
    message_id TEXT,
    conflict_reason TEXT,
    created_at REAL NOT NULL,
    UNIQUE (generation_id, uid)
);

CREATE TABLE IF NOT EXISTS parts (
    id INTEGER PRIMARY KEY,
    message_id INTEGER NOT NULL REFERENCES messages(id),
    origin INTEGER NOT NULL,
    length INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    path TEXT NOT NULL,
    received_at REAL NOT NULL,
    UNIQUE (message_id, origin),
    UNIQUE (message_id, path)
);

CREATE TABLE IF NOT EXISTS flags (
    message_id INTEGER PRIMARY KEY REFERENCES messages(id),
    flags_json TEXT NOT NULL,
    modseq INTEGER,
    observed_at REAL NOT NULL,
    source TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flag_observations (
    id INTEGER PRIMARY KEY,
    message_id INTEGER NOT NULL REFERENCES messages(id),
    flags_json TEXT NOT NULL,
    modseq INTEGER,
    observed_at REAL NOT NULL,
    source TEXT NOT NULL,
    round_id INTEGER
);

CREATE TABLE IF NOT EXISTS round_events (
    id INTEGER PRIMARY KEY,
    round_id INTEGER NOT NULL REFERENCES rounds(id),
    seq INTEGER NOT NULL,
    uid INTEGER,
    kind TEXT NOT NULL,
    detail TEXT,
    observed_at REAL NOT NULL,
    UNIQUE (round_id, seq)
);

CREATE TABLE IF NOT EXISTS inventory (
    round_id INTEGER NOT NULL REFERENCES rounds(id),
    uid INTEGER NOT NULL,
    state TEXT NOT NULL,
    evidence TEXT NOT NULL,
    observed_at REAL NOT NULL,
    PRIMARY KEY (round_id, uid)
);

CREATE TABLE IF NOT EXISTS expunged (
    id INTEGER PRIMARY KEY,
    generation_id INTEGER NOT NULL REFERENCES generations(id),
    uid INTEGER NOT NULL,
    reason TEXT NOT NULL,
    observed_at REAL NOT NULL,
    UNIQUE (generation_id, uid)
);

CREATE TABLE IF NOT EXISTS vanished (
    id INTEGER PRIMARY KEY,
    generation_id INTEGER NOT NULL REFERENCES generations(id),
    uid INTEGER NOT NULL,
    round_id INTEGER NOT NULL REFERENCES rounds(id),
    observed_at REAL NOT NULL,
    UNIQUE (generation_id, uid, round_id)
);

"""


def _now() -> float:
    return time.time()


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), timeout=30.0, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )

    # -- transactions --------------------------------------------------
    @contextmanager
    def transaction(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def close(self) -> None:
        self.conn.close()

    # -- mailboxes / generations --------------------------------------
    def mailbox_id(self, name: str) -> int:
        with self.transaction() as conn:
            conn.execute("INSERT OR IGNORE INTO mailboxes(name) VALUES(?)", (name,))
            row = conn.execute("SELECT id FROM mailboxes WHERE name=?", (name,)).fetchone()
        return int(row["id"])

    def ensure_generation(self, mailbox_id: int, uidvalidity: int) -> sqlite3.Row:
        with self.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO generations(mailbox_id, uidvalidity, opened_at) "
                "VALUES(?, ?, ?)",
                (mailbox_id, uidvalidity, _now()),
            )
            row = conn.execute(
                "SELECT * FROM generations WHERE mailbox_id=? AND uidvalidity=?",
                (mailbox_id, uidvalidity),
            ).fetchone()
        return row

    def generation(self, generation_id: int) -> sqlite3.Row:
        return self.conn.execute(
            "SELECT * FROM generations WHERE id=?", (generation_id,)
        ).fetchone()

    def update_generation_seen(
        self, generation_id: int, uidnext: int | None, highestmodseq: int | None
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE generations SET last_seen_uidnext=?, last_seen_highestmodseq=? WHERE id=?",
                (uidnext, highestmodseq, generation_id),
            )

    def list_generations(self, mailbox: str | None = None) -> list[sqlite3.Row]:
        sql = (
            "SELECT g.*, m.name AS mailbox, "
            "(SELECT COUNT(*) FROM messages x WHERE x.generation_id=g.id AND x.complete=1) AS complete_count, "
            "(SELECT COUNT(*) FROM messages x WHERE x.generation_id=g.id) AS known_count "
            "FROM generations g JOIN mailboxes m ON m.id=g.mailbox_id "
        )
        if mailbox is None:
            return self.conn.execute(sql + "ORDER BY m.name, g.uidvalidity").fetchall()
        return self.conn.execute(
            sql + "WHERE m.name=? ORDER BY g.uidvalidity", (mailbox,)
        ).fetchall()

    # -- rounds --------------------------------------------------------
    def get_open_round(self, generation_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM rounds WHERE generation_id=? AND status='open' "
            "ORDER BY id DESC LIMIT 1",
            (generation_id,),
        ).fetchone()

    def stale_open_rounds(self, mailbox_id: int, generation_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM rounds WHERE mailbox_id=? AND generation_id<>? AND status='open'",
            (mailbox_id, generation_id),
        ).fetchall()

    def mark_round_stale(self, round_id: int, reason: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE rounds SET status='stale', error=?, finished_at=? WHERE id=? AND status='open'",
                (reason[:2000], _now(), round_id),
            )

    def start_round(
        self,
        mailbox_id: int,
        generation_id: int,
        uidnext: int,
        *,
        condstore: bool,
        qresync: bool,
        baseline: int | None,
        full_inventory: bool,
    ) -> sqlite3.Row:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO rounds(mailbox_id, generation_id, started_at, status, "
                "uidnext_at_round, uid_next_progress, condstore, qresync, "
                "highestmodseq_baseline, full_inventory) VALUES(?, ?, ?, 'open', ?, 1, ?, ?, ?, ?)",
                (
                    mailbox_id,
                    generation_id,
                    _now(),
                    uidnext,
                    int(condstore),
                    int(qresync),
                    baseline,
                    int(full_inventory),
                ),
            )
            return conn.execute(
                "SELECT * FROM rounds WHERE id=last_insert_rowid()"
            ).fetchone()

    def set_round_mode(self, round_id: int, *, condstore: bool, qresync: bool, full: bool) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE rounds SET condstore=?, qresync=?, full_inventory=? WHERE id=?",
                (int(condstore), int(qresync), int(full), round_id),
            )

    def advance_progress(self, round_id: int, uid_next_progress: int) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE rounds SET uid_next_progress=? WHERE id=? AND status='open'",
                (uid_next_progress, round_id),
            )

    def finish_round(self, round_id: int, highestmodseq_at_end: int | None) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE rounds SET status='complete', finished_at=?, inventory_done=1, "
                "highestmodseq_at_end=? WHERE id=? AND status='open'",
                (_now(), highestmodseq_at_end, round_id),
            )

    def set_round_error(self, round_id: int, error: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE rounds SET error=? WHERE id=? AND status='open'",
                (error[:2000], round_id),
            )

    def last_complete_round(self, generation_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM rounds WHERE generation_id=? AND status='complete' "
            "ORDER BY id DESC LIMIT 1",
            (generation_id,),
        ).fetchone()

    def rounds(self, generation_id: int | None = None) -> list[sqlite3.Row]:
        if generation_id is None:
            return self.conn.execute(
                "SELECT r.*, g.uidvalidity, m.name AS mailbox FROM rounds r "
                "JOIN generations g ON g.id=r.generation_id "
                "JOIN mailboxes m ON m.id=r.mailbox_id ORDER BY r.id"
            ).fetchall()
        return self.conn.execute(
            "SELECT r.*, g.uidvalidity, m.name AS mailbox FROM rounds r "
            "JOIN generations g ON g.id=r.generation_id "
            "JOIN mailboxes m ON m.id=r.mailbox_id WHERE r.generation_id=? ORDER BY r.id",
            (generation_id,),
        ).fetchall()

    # -- events --------------------------------------------------------
    def add_event(self, round_id: int, uid: int | None, kind: str, detail: str = "") -> None:
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM round_events WHERE round_id=?",
                (round_id,),
            ).fetchone()
            conn.execute(
                "INSERT INTO round_events(round_id, seq, uid, kind, detail, observed_at) "
                "VALUES(?, ?, ?, ?, ?, ?)",
                (round_id, int(row["n"]), uid, kind, detail[:4000], _now()),
            )

    def events(self, round_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM round_events WHERE round_id=? ORDER BY seq", (round_id,)
        ).fetchall()

    # -- messages ------------------------------------------------------
    def message(self, generation_id: int, uid: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM messages WHERE generation_id=? AND uid=?",
            (generation_id, uid),
        ).fetchone()

    def ensure_message(self, generation_id: int, uid: int) -> sqlite3.Row:
        with self.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO messages(generation_id, uid, created_at) VALUES(?, ?, ?)",
                (generation_id, uid, _now()),
            )
            return conn.execute(
                "SELECT * FROM messages WHERE generation_id=? AND uid=?",
                (generation_id, uid),
            ).fetchone()

    def messages_for_generation(self, generation_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM messages WHERE generation_id=? ORDER BY uid", (generation_id,)
        ).fetchall()

    def set_expected_size(self, message_id: int, size: int) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE messages SET expected_size=? WHERE id=?", (size, message_id)
            )

    def pin_body(self, message_id: int) -> None:
        """Mark that bytes for this UID must not be mixed with new responses."""
        with self.transaction() as conn:
            conn.execute(
                "UPDATE messages SET body_digest_pinned=1 WHERE id=?", (message_id,)
            )

    def set_status(self, message_id: int, status: str, reason: str | None = None) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE messages SET status=?, conflict_reason=? WHERE id=?",
                (status, reason, message_id),
            )

    def add_part(
        self, message_id: int, origin: int, length: int, sha256: str, path: str
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO parts(message_id, origin, length, sha256, path, received_at) "
                "VALUES(?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(message_id, origin) DO UPDATE SET length=excluded.length, "
                "sha256=excluded.sha256, path=excluded.path, received_at=excluded.received_at",
                (message_id, origin, length, sha256, path, _now()),
            )

    def parts(self, message_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM parts WHERE message_id=? ORDER BY origin", (message_id,)
        ).fetchall()

    def max_part_end(self, message_id: int) -> int | None:
        row = self.conn.execute(
            "SELECT MAX(origin + length) AS end FROM parts WHERE message_id=?",
            (message_id,),
        ).fetchone()
        return int(row["end"]) if row and row["end"] is not None else None

    def part_by_origin(self, message_id: int, origin: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM parts WHERE message_id=? AND origin=?", (message_id, origin)
        ).fetchone()

    def mark_complete(
        self,
        message_id: int,
        sha256: str,
        length: int,
        path: str,
        message_id_header: str | None,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE messages SET complete=1, status='complete', body_sha256=?, body_length=?, "
                "body_path=?, message_id=?, conflict_reason=NULL WHERE id=?",
                (sha256, length, path, message_id_header, message_id),
            )

    def set_message_id_header(self, message_id: int, header: str | None) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE messages SET message_id=COALESCE(message_id, ?) WHERE id=?",
                (header, message_id),
            )

    # -- flags ---------------------------------------------------------
    def observe_flags(
        self,
        message_id: int,
        flags: list[str],
        modseq: int | None,
        source: str,
        round_id: int | None = None,
    ) -> None:
        payload = json.dumps(sorted(flags))
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO flags(message_id, flags_json, modseq, observed_at, source) "
                "VALUES(?, ?, ?, ?, ?) ON CONFLICT(message_id) DO UPDATE SET "
                "flags_json=excluded.flags_json, modseq=excluded.modseq, "
                "observed_at=excluded.observed_at, source=excluded.source",
                (message_id, payload, modseq, _now(), source),
            )
            conn.execute(
                "INSERT INTO flag_observations(message_id, flags_json, modseq, observed_at, "
                "source, round_id) VALUES(?, ?, ?, ?, ?, ?)",
                (message_id, payload, modseq, _now(), source, round_id),
            )

    def flags(self, message_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM flags WHERE message_id=?", (message_id,)
        ).fetchone()

    # -- expunged / vanished ------------------------------------------
    def mark_expunged(self, generation_id: int, uid: int, reason: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO expunged(generation_id, uid, reason, observed_at) "
                "VALUES(?, ?, ?, ?)",
                (generation_id, uid, reason, _now()),
            )

    def is_expunged(self, generation_id: int, uid: int) -> bool:
        return (
            self.conn.execute(
                "SELECT 1 FROM expunged WHERE generation_id=? AND uid=?",
                (generation_id, uid),
            ).fetchone()
            is not None
        )

    def expunged_uids(self, generation_id: int) -> dict[int, str]:
        rows = self.conn.execute(
            "SELECT uid, reason FROM expunged WHERE generation_id=?", (generation_id,)
        ).fetchall()
        return {int(r["uid"]): r["reason"] for r in rows}

    def add_vanished(self, generation_id: int, uid: int, round_id: int) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO vanished(generation_id, uid, round_id, observed_at) "
                "VALUES(?, ?, ?, ?)",
                (generation_id, uid, round_id, _now()),
            )

    def vanished_uids(self, generation_id: int) -> set[int]:
        rows = self.conn.execute(
            "SELECT uid FROM vanished WHERE generation_id=?", (generation_id,)
        ).fetchall()
        return {int(r["uid"]) for r in rows}

    # -- inventory -----------------------------------------------------
    def set_inventory(self, round_id: int, uid: int, state: str, evidence: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO inventory(round_id, uid, state, evidence, observed_at) "
                "VALUES(?, ?, ?, ?, ?) ON CONFLICT(round_id, uid) DO UPDATE SET "
                "state=excluded.state, evidence=excluded.evidence, observed_at=excluded.observed_at",
                (round_id, uid, state, evidence, _now()),
            )

    def inventory(self, round_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM inventory WHERE round_id=? ORDER BY uid", (round_id,)
        ).fetchall()
