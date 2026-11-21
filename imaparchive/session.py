"""A connection bound to one selected mailbox generation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from .config import Config
from .parse import SelectedInfo, parse_select_greeting
from .protocol import (
    ConnectionLost,
    DigestSink,
    FileLiteralSink,
    LiteralRef,
    ProtocolError,
    Response,
    open_connection,
    quote_mailbox,
)
from .store import Store

_BODY_IN_HEAD = re.compile(rb"\bBODY(?:\.PEEK)?\[", re.I)
_UID_IN_HEAD = re.compile(rb"\bUID\s+([0-9]+)\b")
_ORIGIN_IN_HEAD = re.compile(rb"BODY(?:\.PEEK)?\[[^\]]*\](?:<([0-9]+)>)?", re.I)


class CollectorError(Exception):
    pass


@dataclass
class Selection:
    mailbox: str
    info: SelectedInfo
    caps: set[str]
    condstore: bool
    qresync: bool
    read_only: bool


@dataclass
class BodyLiteral:
    """A fully read literal plus the provenance the response prefix claimed."""

    prefix_uid: int | None
    prefix_origin: int | None
    ref: LiteralRef


@dataclass
class BodyContext:
    """The single body literal the collector is willing to stream to disk.

    Bytes are spooled by advertised length.  Whether the spool file may become
    an archived part is decided by the caller after the enclosing FETCH
    response has been parsed, at which point the UID and origin are known.
    A literal interrupted mid-stream is never committed.  A literal that was
    read in full is retained even if the connection dies before the tagged
    response.
    """

    uid: int
    origin: int
    max_size: int
    rejected: bool = False
    reject_reason: str | None = None
    literals: list[BodyLiteral] = field(default_factory=list)
    # Called as soon as a literal has been read in full *and* its response
    # prefix already named the expected UID and origin.  This is what keeps a
    # verified block when the connection dies before the tagged response.
    commit_early: Callable[[int, LiteralRef], None] | None = None


class _PrefixSink:
    """Record the response-prefix provenance of a spooled literal."""

    def __init__(self, inner: FileLiteralSink, ctx: BodyContext, uid, origin):
        self.inner = inner
        self.ctx = ctx
        self.uid = uid
        self.origin = origin

    def write(self, data: bytes) -> None:
        self.inner.write(data)

    def finish(self) -> LiteralRef:
        ref = self.inner.finish()
        attributed = self.uid == self.ctx.uid and self.origin == self.ctx.origin
        if attributed and self.ctx.commit_early is not None:
            self.ctx.commit_early(self.origin, ref)
        else:
            self.ctx.literals.append(BodyLiteral(self.uid, self.origin, ref))
        return ref

    def abort(self) -> None:
        self.inner.abort()


@dataclass
class Session:
    config: Config
    store: Store
    conn: object | None = None
    selection: Selection | None = None
    body_context: BodyContext | None = None
    lost: Exception | None = None
    _spool: Path | None = None

    def __post_init__(self) -> None:
        self._spool = Path(self.config.data_dir) / "spool"
        self._spool.mkdir(parents=True, exist_ok=True)

    # -- lifecycle -----------------------------------------------------
    def connect(self) -> None:
        self.conn = open_connection(
            host=self.config.host,
            port=self.config.port,
            tls=self.config.tls,
            timeout=self.config.timeout,
            verify_tls=self.config.verify_tls,
            spool_dir=self._spool,
            literal_observer=self._observe_literal,
        )
        self.conn.login(self.config.user, self.config.password)

    def logout(self) -> None:
        if self.conn is None:
            return
        try:
            self.conn.command("LOGOUT", [])
        except Exception:
            pass
        finally:
            self.conn.close()
            self.conn = None
            self.selection = None

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None
        self.selection = None

    # -- commands ------------------------------------------------------
    def capability(self) -> set[str]:
        if self.conn is None:
            raise ConnectionLost("session is not connected")
        return self.conn.capability()

    def command(self, name: str, args: list[str] | None = None, handler=None) -> Response:
        if self.conn is None:
            raise ConnectionLost("session is not connected")
        try:
            return self.conn.command(name, args, handler)
        except ConnectionLost as exc:
            self.lost = exc
            raise
        except (ProtocolError, OSError) as exc:
            self.lost = exc
            raise ConnectionLost(f"{type(exc).__name__}: {exc}") from exc

    def examine(self, args: list[str], caps: set[str]) -> Selection:
        info = SelectedInfo()
        resp = self.command(
            "EXAMINE",
            [quote_mailbox(self.config.mailbox), *args],
            lambda r: parse_select_greeting(r, info),
        )
        if (resp.tagged_status() or "").upper() != "OK":
            raise CollectorError(
                f"cannot EXAMINE {self.config.mailbox!r}: {resp.tagged_text()}"
            )
        if info.uidvalidity is None:
            raise CollectorError("server supplied no UIDVALIDITY; refusing to archive")
        if self.conn is not None:
            caps = caps | self.conn._caps_from(resp)
        nomodseq = info.nomodseq
        condstore = (
            "CONDSTORE" in caps and info.highestmodseq is not None and not nomodseq
        )
        qresync = condstore and "QRESYNC" in caps
        self.selection = Selection(
            mailbox=self.config.mailbox,
            info=info,
            caps=caps,
            condstore=condstore,
            qresync=qresync,
            read_only=True,
        )
        return self.selection

    # -- literal routing ----------------------------------------------
    def _observe_literal(self, size: int, parts: list) -> object:
        """Route a literal.

        The prefix is only used to decide *where* the bytes may go; the identity
        of a body block is proven later from the parsed FETCH response, which is
        why a server that places UID after BODY is still handled correctly.
        """
        head = b"".join(p for p in parts if isinstance(p, bytes))
        if not _BODY_IN_HEAD.search(head):
            return DigestSink(size)
        ctx = self.body_context
        if ctx is None:
            return DigestSink(size)
        uid_match = _UID_IN_HEAD.search(head)
        prefix_uid = int(uid_match.group(1)) if uid_match else None
        origin_match = _ORIGIN_IN_HEAD.search(head)
        prefix_origin = (
            int(origin_match.group(1)) if origin_match and origin_match.group(1) else None
        )
        if size > ctx.max_size:
            ctx.rejected = True
            ctx.reject_reason = (
                f"literal of {size} bytes exceeds the requested {ctx.max_size}"
            )
            return DigestSink(size)
        if prefix_uid is not None and prefix_uid != ctx.uid:
            # Another message's bytes are never written as this message's part.
            ctx.rejected = True
            ctx.reject_reason = (
                f"literal belongs to UID {prefix_uid}, requested {ctx.uid}"
            )
            return DigestSink(size)
        if prefix_origin is not None and prefix_origin != ctx.origin:
            ctx.rejected = True
            ctx.reject_reason = (
                f"literal origin {prefix_origin}, requested {ctx.origin}"
            )
            return DigestSink(size)
        return _PrefixSink(FileLiteralSink(size, self._spool), ctx, prefix_uid, prefix_origin)
