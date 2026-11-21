"""Acceptance tests: the client talks to a scriptable real-TCP IMAP server."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from pathlib import Path

from support import Harness, make_message
from imap_testserver import Hook

from imaparchive.collector import Collector, verify_integrity
from imaparchive.protocol import AuthError, ConnectionLost

UIDVALIDITY = 1000


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def by_uid(catalog) -> dict:
    return {(m["uidvalidity"], m["uid"]): m for m in catalog["messages"]}


def assert_integrity(harness: Harness) -> None:
    store = harness.store()
    try:
        assert verify_integrity(store) == []
    finally:
        store.close()


def complete_uids(catalog, uidvalidity=UIDVALIDITY) -> list[int]:
    return sorted(
        m["uid"]
        for m in catalog["messages"]
        if m["uidvalidity"] == uidvalidity and m["complete"]
    )


# ---------------------------------------------------------------------------
# 1. Core scenario: EXPUNGE during download, cut mid-literal, resume
# ---------------------------------------------------------------------------
def test_expunge_during_download_and_mid_literal_disconnect(state, harness):
    # This scenario runs without QRESYNC so the EXPUNGE arrives as a bare
    # sequence number, which must be recorded as an observation and never
    # interpreted as a UID.
    state.capabilities = {"IMAP4rev1", "CONDSTORE"}
    body2 = make_message(2)
    body9 = make_message(9) + b"\x00\x00A0001 OK not-a-tag\r\n" + b"\r\n.\r\n"
    body20 = make_message(20)
    state.add(body2, uid=2)
    state.add(body9, uid=9)
    state.add(body20, uid=20)
    state.uidnext = 21

    def expunge_2_during_9(handler):
        handler.expunge(2)

    state.hooks.append(Hook("before_fetch", expunge_2_during_9, uid=9))
    # Cut the connection 17 bytes into UID 9's second body chunk.
    state.drop_body.append((9, 2, 17))

    with pytest.raises(ConnectionLost):
        harness.run()

    # No partial body may be published as a complete .eml; progress stays put.
    # UID 2 completed before the EXPUNGE arrived, so it is already archived.
    assert "9.eml" not in harness.message_files(UIDVALIDITY)
    assert "20.eml" not in harness.message_files(UIDVALIDITY)
    catalog = harness.catalog()
    assert catalog["rounds"][0]["status"] == "open"
    assert catalog["rounds"][0]["uid_next_progress"] == 1
    rows = by_uid(catalog)
    assert rows[(UIDVALIDITY, 2)]["complete"]
    assert not rows[(UIDVALIDITY, 9)]["complete"]
    assert not rows[(UIDVALIDITY, 20)]["complete"]

    result = harness.run()
    assert result.status == "complete"
    assert result.resumed is True
    assert result.uidnext_at_round == 21

    catalog = harness.catalog()
    rows = by_uid(catalog)
    assert harness.body(UIDVALIDITY, 9) == body9  # byte-for-byte, only UID 9
    assert rows[(UIDVALIDITY, 9)]["sha256"] == sha(body9)
    assert rows[(UIDVALIDITY, 20)]["sha256"] == sha(body20)
    assert harness.body(UIDVALIDITY, 20) == body20
    assert complete_uids(catalog) == [2, 9, 20]

    # UID 2's body had already been archived when the EXPUNGE arrived; the
    # archived bytes remain available and are not deleted.  The sequence-number
    # observation is retained in order but is never mapped onto a UID.
    inventory = catalog["inventory"][result.round_id]
    assert inventory[2][0] == "complete_expunged"
    assert result.missing == []
    assert harness.body(UIDVALIDITY, 2) == body2  # archived bytes are kept
    expunge_events = [e for e in catalog["events"] if e["kind"] == "expunge_observed"]
    assert expunge_events, "the EXPUNGE observation must be retained in order"
    assert expunge_events[0]["seq"] < max(e["seq"] for e in catalog["events"])
    assert catalog["rounds"][0]["uid_next_progress"] == 21
    assert_integrity(harness)
    # The bytes of UID 9 include literal content that looks like a tag and
    # contains NUL bytes; byte-for-byte equality proves the framing.
    assert b"\x00\x00A0001 OK not-a-tag" in harness.body(UIDVALIDITY, 9)


# ---------------------------------------------------------------------------
# 2. UIDNEXT bound: mail arriving after round one waits for round two
# ---------------------------------------------------------------------------
def test_mail_after_uidnext_is_not_counted_as_missing(state, harness):
    state.add(make_message(2), uid=2)
    state.add(make_message(9), uid=9)
    state.add(make_message(20), uid=20)
    state.uidnext = 21
    late = make_message(21)
    # UID 21 arrives only after the first SELECT has reported UIDNEXT=21.
    state.hooks.append(Hook("after_select", lambda h: h.add_message(late, uid=21)))

    first = harness.run()
    assert first.status == "complete"
    assert first.uidnext_at_round == 21
    assert first.missing == []
    assert first.present == [2, 9, 20]
    assert first.complete == [2, 9, 20]
    assert 21 not in [m["uid"] for m in harness.catalog()["messages"]]

    second = harness.run()
    assert second.status == "complete"
    assert second.uidnext_at_round == 22
    assert 21 in second.complete
    assert harness.body(UIDVALIDITY, 21) == late


# ---------------------------------------------------------------------------
# 3. UIDVALIDITY change: new generation, same UID reused, Message-ID collision
# ---------------------------------------------------------------------------
def test_uidvalidity_change_keeps_both_generations(state, harness):
    first_body = make_message(9, message_id="<same@example.test>")
    state.add(first_body, uid=9)
    state.uidnext = 10
    first = harness.run()
    assert first.status == "complete"

    state.reset_mailbox(uidvalidity=2000)
    reused_body = make_message(9, message_id="<same@example.test>") + b"reused-uid\r\n"
    twin_body = make_message(20, message_id="<same@example.test>")
    state.add(reused_body, uid=9)
    state.add(twin_body, uid=20)
    state.uidnext = 21

    second = harness.run()
    assert second.status == "complete"
    assert second.uidvalidity == 2000
    assert second.generation_id != first.generation_id
    assert second.full_inventory is True  # no baseline crosses generations
    assert second.baseline is None

    catalog = harness.catalog()
    assert catalog["generations"] == [1000, 2000]
    rows = by_uid(catalog)
    assert harness.body(1000, 9) == first_body
    assert harness.body(2000, 9) == reused_body
    assert rows[(1000, 9)]["sha256"] == sha(first_body)
    assert rows[(2000, 9)]["sha256"] == sha(reused_body)
    # Identical Message-ID is never used to merge or skip.
    assert rows[(2000, 20)]["sha256"] == sha(twin_body)
    assert rows[(2000, 9)]["message_id"] == "<same@example.test>"
    assert rows[(2000, 20)]["message_id"] == "<same@example.test>"
    assert rows[(2000, 9)]["sha256"] != rows[(2000, 20)]["sha256"]
    assert_integrity(harness)


# ---------------------------------------------------------------------------
# 4. Flags, VANISHED and incremental == full
# ---------------------------------------------------------------------------
def test_flags_are_observations_not_body_time_history(state, harness):
    body = make_message(1)
    state.add(body, uid=1, flags=["\\Seen"])
    state.uidnext = 2
    harness.run()

    def change_flags(handler):
        handler.set_flags(1, ["\\Seen", "\\Flagged"])

    state.hooks.append(Hook("after_select", change_flags))
    result = harness.run()
    assert result.status == "complete"
    catalog = harness.catalog()
    assert json.loads(catalog["flags"][1]) == ["\\Flagged", "\\Seen"]
    observed = [
        e for e in catalog["events"] if e["kind"] == "flags_observed"
    ]
    assert observed
    assert "FLAGS" in observed[-1]["detail"]
    # The body was never re-downloaded.
    assert harness.body(UIDVALIDITY, 1) == body


def test_vanished_yields_explicit_deletion_evidence(state, harness):
    for uid in (2, 9, 20):
        state.add(make_message(uid), uid=uid)
    state.uidnext = 21
    harness.run()

    def drop_20(handler):
        handler.expunge(20)

    state.hooks.append(Hook("after_select", drop_20))
    result = harness.run()
    assert result.status == "complete"
    catalog = harness.catalog()
    assert 20 in catalog["expunged"]
    assert any(e["kind"] == "vanished" for e in catalog["events"])
    assert 2 in result.complete and 9 in result.complete
    assert 2 not in catalog["expunged"] and 9 not in catalog["expunged"]


def test_expunge_without_qresync_seen_as_sequence_number(state, harness):
    for uid in (2, 9, 20):
        state.add(make_message(uid), uid=uid)
    state.uidnext = 21
    harness.run()

    body30 = make_message(30)
    state.add(body30, uid=30)
    state.uidnext = 31

    def drop_9(handler):
        handler.expunge(9)

    state.hooks.append(Hook("before_fetch", drop_9, uid=30))
    state.capabilities = {"IMAP4rev1", "CONDSTORE"}
    # The EXPUNGE arrives while UID 30's literal is being transferred, and the
    # connection dies mid-literal: the observation must survive the restart.
    state.drop_body.append((30, 1, 5))
    with pytest.raises(ConnectionLost):
        harness.run()
    result = harness.run()
    assert result.status == "complete"
    catalog = harness.catalog()
    assert 9 in catalog["expunged"]
    observed = [e for e in catalog["events"] if e["kind"] == "expunge_observed"]
    assert observed, "sequence-number EXPUNGE must be recorded as an observation"
    assert "never a UID" in observed[0]["detail"]
    # A sequence-number EXPUNGE is never mapped onto a UID.
    assert 2 not in catalog["expunged"] and 20 not in catalog["expunged"]
    # UID 9's body was archived in round one and is kept even though the
    # message later disappeared from the server.
    assert complete_uids(catalog) == [2, 9, 20, 30]
    assert harness.body(UIDVALIDITY, 9) == make_message(9)
    assert harness.body(UIDVALIDITY, 30) == body30


def test_incremental_matches_full_inventory(state, harness):
    for uid in (2, 9, 20):
        state.add(make_message(uid), uid=uid)
    state.uidnext = 21
    harness.run()

    state.remove(2)
    with state.lock:
        msg = state.messages[9]
        msg.flags = ["\\Seen", "\\Answered"]
        msg.modseq = state.bump_modseq()

    incremental = harness.run()
    assert incremental.condstore is True
    assert incremental.qresync is True
    assert incremental.baseline is not None
    assert incremental.full_inventory is False
    incremental_catalog = harness.catalog()

    store = harness.store()
    try:
        store.conn.execute("UPDATE rounds SET highestmodseq_at_end=NULL")
    finally:
        store.close()
    full = harness.run()
    assert full.full_inventory is True
    assert full.present == incremental.present
    assert full.complete == incremental.complete
    assert full.missing == incremental.missing
    assert full.unresolved == incremental.unresolved
    catalog = harness.catalog()
    assert set(catalog["expunged"]) == set(incremental_catalog["expunged"])
    assert complete_uids(catalog) == [2, 9, 20]


# ---------------------------------------------------------------------------
# 5. Capability downgrades
# ---------------------------------------------------------------------------
def test_no_qresync_still_archives(state, harness):
    state.capabilities = {"IMAP4rev1", "CONDSTORE"}
    state.add(make_message(1), uid=1)
    state.uidnext = 2
    result = harness.run()
    assert result.status == "complete"
    assert result.qresync is False
    catalog = harness.catalog()
    assert catalog["rounds"][0]["qresync"] == 0
    assert catalog["rounds"][0]["full_inventory"] == 1


def test_nomodseq_downgrades_to_full_inventory(state, harness):
    state.add(make_message(1), uid=1)
    state.uidnext = 2
    harness.run()
    state.nomodseq = True
    result = harness.run()
    assert result.status == "complete"
    assert result.condstore is False
    assert result.full_inventory is True
    assert result.baseline is None
    catalog = harness.catalog()
    assert catalog["rounds"][-1]["full_inventory"] == 1
    assert all(e["kind"] != "metadata_incremental" for e in catalog["events"])


def test_no_condstore_capability(state, harness):
    state.capabilities = {"IMAP4rev1"}
    state.add(make_message(1), uid=1)
    state.uidnext = 2
    result = harness.run()
    assert result.status == "complete"
    assert result.condstore is False and result.qresync is False
    assert result.full_inventory is True
    assert harness.body(UIDVALIDITY, 1) == make_message(1)


# ---------------------------------------------------------------------------
# 6. Degenerate mailboxes
# ---------------------------------------------------------------------------
def test_empty_mailbox(state, harness):
    result = harness.run()
    assert result.status == "complete"
    assert result.present == []
    assert result.complete == []
    assert result.progress == 1
    assert harness.catalog()["messages"] == []
    assert_integrity(harness)


def test_expunge_of_not_yet_downloaded_uid_is_missing_with_evidence(state, harness):
    state.add(make_message(9), uid=9)
    state.add(make_message(20), uid=20)
    state.uidnext = 21

    def drop_20_during_9(handler):
        handler.expunge(20)

    state.hooks.append(Hook("before_fetch", drop_20_during_9, uid=9))
    result = harness.run()
    assert result.status == "complete"
    assert 20 in result.missing
    state_, evidence = catalog_state(harness, result.round_id, 20)
    assert state_ == "missing"
    assert evidence in {"expunge_evidence", "absent_from_complete_final_inventory"}
    assert "VANISHED" in harness.catalog()["expunged"][20] or (
        harness.catalog()["expunged"][20].startswith("absent_")
    )
    assert harness.body(UIDVALIDITY, 9) == make_message(9)
    assert "20.eml" not in harness.message_files(UIDVALIDITY)
    assert_integrity(harness)


def catalog_state(harness: Harness, round_id: int, uid: int):
    return harness.catalog()["inventory"][round_id][uid]


def test_uid_vanishes_before_body_fetch(state, harness):
    state.add(make_message(2), uid=2)
    body9 = make_message(9)
    state.add(body9, uid=9)
    state.uidnext = 21

    def vanish_2(handler):
        if handler.state.messages.pop(2, None) is not None:
            handler.state.bump_modseq()

    state.hooks.append(Hook("before_fetch", vanish_2, uid=2))
    result = harness.run()
    assert result.status == "complete"
    assert 2 in result.missing
    assert harness.catalog()["expunged"].get(2) is not None
    assert harness.body(UIDVALIDITY, 9) == body9
    assert_integrity(harness)


def test_zero_length_message(state, harness):
    state.add(b"", uid=1)
    state.uidnext = 2
    result = harness.run()
    assert result.status == "complete"
    assert harness.body(UIDVALIDITY, 1) == b""
    assert harness.catalog()["messages"][0]["complete"]


def test_server_refuses_flag_mutation(state, harness):
    """The collector must never issue STORE/EXPUNGE/COPY."""
    state.add(make_message(1), uid=1)
    state.uidnext = 2
    harness.run()
    attempts = [e for e in state.log if e["kind"] == "mutation_attempt"]
    assert attempts == []


# ---------------------------------------------------------------------------
# 7. Credentials
# ---------------------------------------------------------------------------
def test_authentication_failure_leaves_no_archive(harness):
    bad = replace(harness.config, password="wrong-password-xyz")
    store = harness.store()
    try:
        with pytest.raises(AuthError):
            Collector(bad, store, harness.layout).run()
    finally:
        store.close()
    assert harness.message_files(UIDVALIDITY) == []
    assert harness.catalog()["messages"] == []
    assert b"wrong-password-xyz" not in harness.layout.db_path.read_bytes()


def test_cli_auth_failure_exit_code(harness, monkeypatch):
    bad = replace(harness.config, password="wrong-password-xyz")
    from imaparchive.cli import main

    monkeypatch.setenv("IMAP_HOST", bad.host)
    monkeypatch.setenv("IMAP_PORT", str(bad.port))
    monkeypatch.setenv("IMAP_USER", bad.user)
    monkeypatch.setenv("IMAP_PASSWORD", bad.password)
    monkeypatch.setenv("IMAP_TLS", "none")
    monkeypatch.setenv("IMAPARCHIVE_DATA", str(bad.data_dir))
    assert main(["collect"]) == 77


# ---------------------------------------------------------------------------
# 8. Crash before progress commit
# ---------------------------------------------------------------------------
def test_crash_before_progress_commit(state, harness):
    bodies = {uid: make_message(uid) for uid in (2, 9, 20)}
    for uid, body in bodies.items():
        state.add(body, uid=uid)
    state.uidnext = 21
    state.drop_body.append((20, 1, 3))

    with pytest.raises(ConnectionLost):
        harness.run()

    catalog = harness.catalog()
    assert catalog["rounds"][0]["status"] == "open"
    assert catalog["rounds"][0]["uid_next_progress"] == 1
    rows = by_uid(catalog)
    # UIDs 2 and 9 were already complete; only the interrupted UID 20 is
    # missing a published body.  Progress never advanced past an incomplete UID.
    assert rows[(UIDVALIDITY, 2)]["complete"] and rows[(UIDVALIDITY, 9)]["complete"]
    assert not rows[(UIDVALIDITY, 20)]["complete"]
    assert "20.eml" not in harness.message_files(UIDVALIDITY)

    result = harness.run()
    assert result.status == "complete"
    assert result.resumed is True
    for uid, body in bodies.items():
        assert harness.body(UIDVALIDITY, uid) == body
    assert result.uidnext_at_round == 21
    assert_integrity(harness)


# ---------------------------------------------------------------------------
# 9. "No reply" is not deletion
# ---------------------------------------------------------------------------
def test_missing_fetch_reply_is_not_deletion(state, harness):
    body9 = make_message(9)
    state.add(make_message(2), uid=2)
    state.add(body9, uid=9)
    state.uidnext = 21
    # The server answers OK but sends no FETCH data for UID 2 in this round.
    state.suppress_fetch.add(2)

    result = harness.run()
    # UID 2 is still listed, so it is unresolved, not missing.
    assert result.status == "incomplete"
    assert 2 in result.unresolved
    assert 2 not in result.missing
    assert 2 not in harness.catalog()["expunged"]
    assert result.progress == 2
    assert 9 in result.complete
    assert harness.body(UIDVALIDITY, 9) == body9
    assert_integrity(harness)

    state.suppress_fetch.discard(2)
    result2 = harness.run()
    assert result2.status == "complete"
    assert result2.resumed is True
    assert 2 in result2.complete
    assert harness.body(UIDVALIDITY, 2) == make_message(2)


# ---------------------------------------------------------------------------
# 10. Same generation, changed bytes: never silently replaced
# ---------------------------------------------------------------------------
def test_changed_bytes_under_same_uid_keep_original(state, harness):
    original = make_message(9)
    state.add(original, uid=9)
    state.uidnext = 10
    harness.run()
    assert harness.body(UIDVALIDITY, 9) == original

    # The server now serves different bytes for the same UID (same generation,
    # not permitted); the archived original must not be replaced.
    replacement = make_message(9) + b"silently-different\r\n"
    with state.lock:
        state.messages[9].body = replacement
        state.messages[9].modseq = state.bump_modseq()

    result = harness.run()
    assert result.status == "complete"
    catalog = harness.catalog()
    row = by_uid(catalog)[(UIDVALIDITY, 9)]
    assert row["sha256"] == sha(original)
    assert harness.body(UIDVALIDITY, 9) == original
    assert row["status"] == "conflict_kept_original"
    assert any(e["kind"] == "conflict_kept_original" for e in catalog["events"])
    # The UID is still reported: the original verified body remains delivered.
    assert 9 in result.complete
    assert 9 in result.conflict
    assert_integrity(harness)


# ---------------------------------------------------------------------------
# 11. UIDVALIDITY changes while a round is open
# ---------------------------------------------------------------------------
def test_uidvalidity_change_with_open_round_closes_it(state, harness):
    state.add(make_message(2), uid=2)
    state.add(make_message(9), uid=9)
    state.uidnext = 21
    state.drop_body.append((9, 1, 5))
    with pytest.raises(ConnectionLost):
        harness.run()
    assert harness.catalog()["rounds"][0]["status"] == "open"

    state.reset_mailbox(uidvalidity=3000)
    new_body = make_message(9) + b"third-generation\r\n"
    state.add(new_body, uid=9)
    state.uidnext = 10

    result = harness.run()
    assert result.status == "complete"
    assert result.uidvalidity == 3000
    assert result.full_inventory is True
    assert result.baseline is None
    assert result.uidnext_at_round == 10
    catalog = harness.catalog()
    old_round = catalog["rounds"][0]
    assert old_round["status"] == "stale"
    assert "UIDVALIDITY" in (old_round["error"] or "")
    assert harness.body(3000, 9) == new_body
    assert harness.body(1000, 2) == make_message(2)  # old generation intact
    assert catalog["generations"] == [1000, 3000]


# ---------------------------------------------------------------------------
# 12. Literal containing tag/crlf/NUL bytes survives protocol parsing
# ---------------------------------------------------------------------------
def test_literal_with_protocol_lookalikes(state, harness):
    inner = (
        b"A0001 OK fake tagged\r\n"
        b"* 9 FETCH (UID 20 BODY[] {5}\r\nxxxxx)\r\n"
        b"\x00\x01\x02\r\n.\r\n"
        b")\r\n"
    )
    body = make_message(9, body=inner)
    state.add(body, uid=9)
    state.uidnext = 10
    result = harness.run()
    assert result.status == "complete"
    assert harness.body(UIDVALIDITY, 9) == body
    rows = by_uid(harness.catalog())
    assert rows[(UIDVALIDITY, 9)]["sha256"] == sha(body)


# ---------------------------------------------------------------------------
# 13. A literal read in full before the cut is kept; the next round resumes
#     after it rather than re-downloading it.
# ---------------------------------------------------------------------------
def test_fully_read_literal_survives_connection_loss(state, harness):
    body = make_message(9, body_lines=80)  # ~3.4 KiB
    state.add(body, uid=9)
    state.uidnext = 10
    # Chunk size is 256.  The first FETCH is the metadata pass, so counting the
    # third FETCH means the connection is cut right after the second body
    # literal has been read in full but before the tagged response.
    cut_after_chunk = 3
    fetches = {"count": 0}

    def cut(handler):
        fetches["count"] += 1
        if fetches["count"] == cut_after_chunk:
            # Let the server finish this literal, then kill the connection.
            def killer(h=handler):
                h.hard_close()

            state.hooks.append(Hook("after_body", killer, uid=9))

    state.hooks.append(Hook("before_fetch", cut, uid=9, once=False))

    with pytest.raises(ConnectionLost):
        harness.run()

    catalog = harness.catalog()
    # The first two chunks were fully verified and must be on disk.
    assert harness.part_files(UIDVALIDITY) == ["9.0.part", "9.256.part"]
    assert not any(m["complete"] for m in catalog["messages"])
    assert catalog["rounds"][0]["uid_next_progress"] == 1

    result = harness.run()
    assert result.status == "complete"
    assert harness.body(UIDVALIDITY, 9) == body
    # The resumed run asked for the rest starting at 512, not from zero.
    resumed_fetch_origins = [
        entry["origin"]
        for entry in state.log
        if entry["kind"] == "fetch_body" and entry["uid"] == 9
    ]
    assert 512 in resumed_fetch_origins
    assert resumed_fetch_origins.count(0) == 1


# ---------------------------------------------------------------------------
# 14. A resumed round must not advertise itself as a complete delivery when
#     it was interrupted; progress may become queryable later.
# ---------------------------------------------------------------------------
def test_check_reports_open_round_and_resume(state, harness):
    state.add(make_message(9), uid=9)
    state.uidnext = 10
    state.drop_body.append((9, 3, 7))
    with pytest.raises(ConnectionLost):
        harness.run()
    catalog = harness.catalog()
    assert catalog["rounds"][0]["status"] == "open"
    assert harness.catalog()["rounds"][0]["uid_next_progress"] == 1

    from imaparchive.cli import main
    import os
    import subprocess
    import sys

    # `check` is offline and must not need credentials.  Run it in a child
    # process with an empty credential environment to prove it.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(Path(__file__).resolve().parent.parent),
        "IMAPARCHIVE_DATA": str(harness.config.data_dir),
        "IMAP_MAILBOX": "INBOX",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "imaparchive", "check"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "open" in proc.stdout

    result = harness.run()
    assert result.status == "complete"
    assert result.resumed is True
    assert harness.body(UIDVALIDITY, 9) == make_message(9)
