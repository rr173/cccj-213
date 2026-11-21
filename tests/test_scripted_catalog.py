"""The expected catalogue is projected from the test server's event script.

Nothing in this test reads the collector's own bookkeeping to decide what the
answer should be: the expectation comes from the sequence of scripted server
events, and is then compared against the on-disk archive byte for byte.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from support import Harness, make_message
from imap_testserver import Hook


@dataclass
class Script:
    """Server-side event script plus the catalogue it implies."""

    adds: list[tuple[int, bytes]] = field(default_factory=list)
    expunges: list[int] = field(default_factory=list)

    def add(self, uid: int, body: bytes) -> None:
        self.adds.append((uid, body))

    def expected_bodies(self) -> dict[int, str]:
        return {uid: hashlib.sha256(body).hexdigest() for uid, body in self.adds}

    def replay(self, log: list[dict]) -> dict[int, str | None]:
        """Project uid -> sha256, or ``None`` if the server deleted it.

        The projection comes from the scripted server log only; it never reads
        the collector's catalogue.
        """
        live: dict[int, str] = dict(self.expected_bodies())
        for entry in log:
            if entry["kind"] == "expunge" and entry.get("ok"):
                live.pop(int(entry["uid"]), None)
        return {uid: live.get(uid) for uid, _ in self.adds}


def test_catalog_matches_scripted_events(state, harness: Harness):
    script = Script()
    script.add(2, make_message(2))
    script.add(9, make_message(9) + b"\x00tag-lookalike\r\n")
    script.add(20, make_message(20, message_id="<shared@example.test>"))
    for uid, body in script.adds:
        state.add(body, uid=uid)
    state.uidnext = 21
    late = make_message(21, message_id="<shared@example.test>")
    script.add(21, late)

    # The scripted server announces UID 21 only after the first SELECT.
    state.hooks.append(Hook("after_select", lambda h: h.add_message(late, uid=21)))

    first = harness.run()
    assert first.status == "complete"
    assert first.uidnext_at_round == 21
    # UID 21 arrived after the round's bound and is not treated as missing.
    assert first.missing == []
    assert 21 not in first.present

    second = harness.run()
    assert second.status == "complete"
    assert second.uidnext_at_round == 22
    assert 21 in second.complete

    # Now delete a message on the server and run a third round.
    def drop_20(handler):
        handler.expunge(20)

    state.hooks.append(Hook("after_select", drop_20))
    third = harness.run()
    assert third.status == "complete"
    # UID 20 had already been archived; its disappearance is recorded as an
    # observation but the archive keeps the bytes.
    assert 20 in third.expunged_complete
    assert harness.catalog()["expunged"].get(20) is not None

    live = script.replay(state.log)
    catalog = harness.catalog()
    archived = {
        (m["uidvalidity"], m["uid"]): m for m in catalog["messages"] if m["complete"]
    }
    # Every scripted message that was ever archived is archived with exactly
    # the bytes the script supplied, regardless of expunges or duplicate
    # Message-ID values.
    expected = script.expected_bodies()
    for uid, sha in expected.items():
        assert archived[(1000, uid)]["sha256"] == sha, uid
        path = harness.body_path(1000, uid)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == sha
        assert path.stat().st_size == len(dict(script.adds)[uid])
    # UIDs still live on the server at the end must be present in the inventory;
    # UIDs the script expunged must not be.
    for uid, sha in live.items():
        if sha is None:
            assert uid not in third.present
        else:
            assert uid in third.present
    # The duplicated Message-ID never collapsed two logical messages.
    assert archived[(1000, 20)]["message_id"] == "<shared@example.test>"
    assert archived[(1000, 21)]["message_id"] == "<shared@example.test>"
    assert archived[(1000, 20)]["sha256"] != archived[(1000, 21)]["sha256"]
