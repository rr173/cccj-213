"""Offline export / integrity tests, with no server running."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from support import Harness, make_message

from imaparchive.archive import export
from imaparchive.collector import verify_integrity


def test_export_requires_no_network(state, harness):
    state.add(make_message(1), uid=1)
    bodies = {9: make_message(9), 20: make_message(20)}
    for uid, body in bodies.items():
        state.add(body, uid=uid)
    state.uidnext = 21
    harness.run()

    offline = Harness(
        root=harness.root,
        config=replace(harness.config, host="192.0.2.1", port=1),
        layout=harness.layout,
    )
    out = harness.root / "export"
    store = offline.store()
    try:
        summary = export(store, out)
        assert verify_integrity(store) == []
    finally:
        store.close()
    assert summary["exported"] == 3
    records = [
        json.loads(line) for line in (out / "manifest.jsonl").read_text().splitlines()
    ]
    assert [r["uid"] for r in records] == [1, 9, 20]
    for record in records:
        path = Path(record["path"])
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        assert len(data) == record["length"]
    assert (out / "INBOX" / "1000" / "messages" / "9.eml").read_bytes() == bodies[9]


def test_export_detects_missing_body(state, harness):
    state.add(make_message(1), uid=1)
    state.uidnext = 2
    harness.run()
    harness.body_path(1000, 1).unlink()
    store = harness.store()
    try:
        with pytest.raises(Exception):
            export(store, harness.root / "export")
    finally:
        store.close()


def test_verify_detects_progress_past_missing_body(state, harness):
    state.add(make_message(1), uid=1)
    state.add(make_message(2), uid=2)
    state.uidnext = 3
    harness.run()
    store = harness.store()
    try:
        store.conn.execute(
            "UPDATE messages SET complete=0, body_path=NULL, body_sha256=NULL "
            "WHERE uid=1"
        )
        problems = verify_integrity(store)
    finally:
        store.close()
    assert problems
    assert "UID 1" in problems[0]


def test_export_does_not_touch_server(state, harness):
    state.add(make_message(1), uid=1)
    state.uidnext = 2
    harness.run()
    before = len(state.log)
    store = harness.store()
    try:
        export(store, harness.root / "export")
    finally:
        store.close()
    assert len(state.log) == before, "export must not issue IMAP commands"
