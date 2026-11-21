"""Protocol-level tests with no network: framing, literals, tag alignment."""

from __future__ import annotations


import pytest

from imaparchive.parse import is_fetch, parse_fetch, tokenize
from imaparchive.protocol import (
    FileLiteralSink,
    ResponseParser,
    format_uid_set,
    quote_mailbox,
)


class FakeSocket:
    """Socket stand-in that hands out scripted bytes in arbitrary slices."""

    def __init__(self, payload: bytes, slices: tuple[int, ...] = (7, 1, 13, 1024)):
        self.payload = payload
        self.offset = 0
        self.slices = slices
        self.index = 0

    def recv(self, _size: int) -> bytes:
        if self.offset >= len(self.payload):
            return b""
        take = self.slices[self.index % len(self.slices)]
        self.index += 1
        chunk = self.payload[self.offset : self.offset + take]
        self.offset += len(chunk)
        return chunk

    def settimeout(self, _timeout) -> None:
        return None

    def close(self) -> None:
        return None


def parse_all(payload: bytes, factory=None):
    from imaparchive.protocol import _Reader

    reader = _Reader(FakeSocket(payload), 5.0)  # type: ignore[arg-type]
    parser = ResponseParser(reader, factory)
    out = []
    while True:
        try:
            out.append(parser.next_response())
        except Exception:
            break
    return out


def test_literal_is_consumed_by_declared_length_not_lines():
    inner = b"A0001 OK fake\r\n\x00\x00\r\n)tag\r\n)\r\n* 9 EXPUNGE\r\n"
    payload = (
        b"* 1 FETCH (UID 9 BODY[] {" + str(len(inner)).encode() + b"}\r\n"
        + inner
        + b")\r\n"
        b"A0002 OK done\r\n"
    )
    from imaparchive.protocol import _Reader

    reader = _Reader(FakeSocket(payload), 5.0)  # type: ignore[arg-type]
    parser = ResponseParser(reader)
    first = parser.next_response()
    second = parser.next_response()
    assert first.literals[0].size == len(inner)
    assert first.literals[0].materialized == inner
    assert second.first == b"A0002 OK done"


def test_unknown_responses_keep_literal_boundary():
    payload = (
        b"* 77 WEIRDNESS (X Y) {12}\r\nhello\r\nworld"
        b")\r\n"
        b"* OK still alive\r\n"
    )
    from imaparchive.protocol import _Reader

    reader = _Reader(FakeSocket(payload), 5.0)  # type: ignore[arg-type]
    parser = ResponseParser(reader)
    first = parser.next_response()
    second = parser.next_response()
    assert first.literals[0].materialized == b"hello\r\nworld"
    assert second.first == b"* OK still alive"


def test_zero_length_literal():
    from imaparchive.protocol import _Reader

    reader = _Reader(FakeSocket(b"* 1 FETCH (BODY[] {0}\r\n)\r\n"), 5.0)  # type: ignore[arg-type]
    resp = ResponseParser(reader).next_response()
    assert resp.literals[0].size == 0
    assert resp.literals[0].sha256


def test_truncated_literal_raises_instead_of_swallowing():
    from imaparchive.protocol import _Reader

    reader = _Reader(FakeSocket(b"* 1 FETCH (BODY[] {100}\r\nshort"), 5.0)  # type: ignore[arg-type]
    parser = ResponseParser(reader)
    with pytest.raises(Exception) as excinfo:
        parser.next_response()
    assert "closed" in str(excinfo.value) or "short" in str(excinfo.value)


def test_file_sink_aborts_cleanly(tmp_path):
    sink = FileLiteralSink(10, tmp_path)
    sink.write(b"abc")
    path = sink.path
    sink.abort()
    assert not path.exists()


def test_uid_set_round_trip():
    assert format_uid_set([1, 2, 3, 9, 20]) == "1:3,9,20"
    assert format_uid_set([]) == ""
    assert format_uid_set([5]) == "5"


def test_quote_mailbox_rejects_control_characters():
    assert quote_mailbox("INBOX") == '"INBOX"'
    assert quote_mailbox('we"ird') == '"we\\"ird"'
    with pytest.raises(ValueError):
        quote_mailbox("bad\r\nname")


def test_fetch_parse_with_trailing_garbage_literal():
    from imaparchive.protocol import LiteralRef, Response

    # The parser yields the prefix without the literal marker, then the ref.
    resp = Response(
        parts=[
            b"* 1 FETCH (UID 20 FLAGS (\\Seen) BODY[]<0> ",
            LiteralRef(size=5, sha256="x", materialized=b"a\r\nb)"),
            b")\r\n",
        ]
    )
    assert is_fetch(resp)
    data = parse_fetch(resp)
    assert data.uid == 20
    assert data.flags == ["\\Seen"]
    origin, literal = data.body("")
    assert origin == 0 and literal.materialized == b"a\r\nb)"
    tree = tokenize(resp)
    assert isinstance(tree[3], list)
