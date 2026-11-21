"""IMAP wire protocol framing.

This module intentionally does not parse message bodies as lines.  A literal is
read by its advertised octet count, so CRLF, tag-looking text and NUL bytes in a
literal can never be mistaken for protocol.  Anything the collector does not
understand still has its literals consumed exactly, leaving the stream aligned.
"""

from __future__ import annotations

import hashlib
import os
import re
import socket
import ssl
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Protocol

MAX_LINE = 512 * 1024
_LITERAL_END = re.compile(rb"^(?P<prefix>.*)\{(?P<size>[0-9]+)(?P<plus>\+?)\}$")


class ImapError(Exception):
    pass


class ConnectionLost(ImapError):
    pass


class ProtocolError(ImapError):
    pass


class AuthError(ImapError):
    pass


class CommandFailed(ImapError):
    def __init__(self, command: str, status: str, text: str):
        super().__init__(f"{command} failed: {status} {text}".strip())
        self.command = command
        self.status = status
        self.text = text


class LiteralSink(Protocol):
    def write(self, data: bytes) -> None: ...
    def finish(self) -> "LiteralRef": ...
    def abort(self) -> None: ...


@dataclass
class LiteralRef:
    size: int
    sha256: str
    path: str | None = None
    materialized: bytes | None = None
    truncated_digest: bool = False

    def text_marker(self) -> str:
        return f"<literal {self.size} bytes sha256:{self.sha256}>"


class DigestSink:
    """Consume a literal, retaining only a digest (and tiny payloads)."""

    def __init__(self, size: int, keep_limit: int = 65536):
        self.size = size
        self._hash = hashlib.sha256()
        self._buf = bytearray()
        self._keep_limit = keep_limit
        self._written = 0

    def write(self, data: bytes) -> None:
        self._hash.update(data)
        self._written += len(data)
        if len(self._buf) + len(data) <= self._keep_limit:
            self._buf.extend(data)

    def finish(self) -> LiteralRef:
        if self._written != self.size:
            raise ProtocolError(
                f"literal short: declared {self.size}, got {self._written}"
            )
        data = bytes(self._buf) if self._written <= self._keep_limit else None
        return LiteralRef(
            size=self.size,
            sha256=self._hash.hexdigest(),
            materialized=data,
            truncated_digest=data is None,
        )

    def abort(self) -> None:
        return None


class FileLiteralSink:
    """Stream a literal to a private temporary file.

    The file is not published to the archive until the enclosing response has
    been fully parsed and the collector has proven which UID it belongs to.
    """

    def __init__(self, size: int, directory: Path):
        self.size = size
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix="lit-", suffix=".tmp", dir=str(directory))
        self.path = Path(name)
        self._file = os.fdopen(fd, "wb")
        self._hash = hashlib.sha256()
        self._written = 0
        self._finished = False

    def write(self, data: bytes) -> None:
        self._file.write(data)
        self._hash.update(data)
        self._written += len(data)

    def finish(self) -> LiteralRef:
        if self._written != self.size:
            raise ProtocolError(
                f"literal short: declared {self.size}, got {self._written}"
            )
        self._file.flush()
        os.fsync(self._file.fileno())
        self._file.close()
        self._finished = True
        return LiteralRef(
            size=self.size,
            sha256=self._hash.hexdigest(),
            path=str(self.path),
        )

    def abort(self) -> None:
        # A literal whose advertised octets were all read is complete and must
        # survive a connection loss that happens after it; only a short literal
        # is removed.
        try:
            if not self._file.closed:
                self._file.close()
        finally:
            if not self._finished:
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass


class _Reader:
    def __init__(self, sock: socket.socket, timeout: float):
        self.sock = sock
        self.timeout = timeout
        self._buf = bytearray()
        sock.settimeout(timeout)

    def _recv(self) -> None:
        try:
            data = self.sock.recv(65536)
        except (socket.timeout, TimeoutError) as exc:
            raise ConnectionLost("socket timeout while waiting for data") from exc
        except OSError as exc:
            raise ConnectionLost(f"socket error: {exc}") from exc
        if not data:
            raise ConnectionLost("server closed the connection")
        self._buf.extend(data)

    def readline(self) -> bytes:
        while True:
            idx = self._buf.find(b"\r\n")
            if idx >= 0:
                line = bytes(self._buf[:idx])
                del self._buf[: idx + 2]
                return line
            if len(self._buf) > MAX_LINE:
                raise ProtocolError("response line exceeds safety limit")
            self._recv()

    def read_exact(self, count: int, sink: LiteralSink) -> None:
        remaining = count
        while remaining:
            if not self._buf:
                self._recv()
            take = min(remaining, len(self._buf))
            chunk = bytes(self._buf[:take])
            del self._buf[:take]
            sink.write(chunk)
            remaining -= take


@dataclass
class Response:
    parts: list[bytes | LiteralRef]
    received_at: float = field(default_factory=time.time)

    @property
    def first(self) -> bytes:
        return self.parts[0] if self.parts else b""

    @property
    def literals(self) -> list[LiteralRef]:
        return [p for p in self.parts if isinstance(p, LiteralRef)]

    def text_parts(self) -> list[bytes]:
        return [p for p in self.parts if isinstance(p, bytes)]

    def head_text(self, limit: int = 4096) -> str:
        return self.first.decode("utf-8", "replace")[:limit]

    def display_text(self, limit: int = 8192) -> str:
        out = []
        for part in self.parts:
            if isinstance(part, bytes):
                out.append(part.decode("utf-8", "replace"))
            else:
                out.append(part.text_marker())
        text = "".join(out)
        return text[:limit]

    def is_tagged(self) -> bool:
        head = self.first
        if not head or head.startswith(b"*") or head.startswith(b"+"):
            return False
        return b" " in head

    def tokens(self) -> list[str]:
        head = self.first.decode("ascii", "replace")
        return head.split()

    def tagged_tag(self) -> str | None:
        if not self.is_tagged():
            return None
        return self.tokens()[0]

    def tagged_status(self) -> str | None:
        if not self.is_tagged():
            return None
        toks = self.tokens()
        return toks[1].upper() if len(toks) > 1 else None

    def tagged_text(self) -> str:
        toks = self.tokens()
        return " ".join(toks[2:]) if len(toks) > 2 else ""

    def response_code(self) -> str | None:
        """First [CODE ...] in the head (or tagged OK text)."""
        text = self.head_text().replace("\r", " ")
        match = re.search(r"\[([A-Za-z0-9._-]+)(?:\s[^\]]*)?\]", text)
        return match.group(1).upper() if match else None


LiteralFactory = Callable[[int, list[bytes | LiteralRef]], LiteralSink]
AnySinkFactory = Callable[[int], LiteralSink]


class ResponseParser:
    def __init__(
        self,
        reader: _Reader,
        literal_factory: Callable[[int, list[bytes | LiteralRef]], LiteralSink] | None = None,
    ):
        self.reader = reader
        self.literal_factory = literal_factory or (
            lambda size, parts: DigestSink(size)
        )

    def next_response(self) -> Response:
        parts: list[bytes | LiteralRef] = []
        pending_sinks: list[LiteralSink] = []
        try:
            while True:
                line = self.reader.readline()
                match = _LITERAL_END.match(line)
                if match:
                    parts.append(match.group("prefix"))
                    size = int(match.group("size"))
                    sink = self.literal_factory(size, list(parts))
                    pending_sinks.append(sink)
                    self.reader.read_exact(size, sink)
                    parts.append(sink.finish())
                    continue
                parts.append(line)
                break
        except BaseException:
            for sink in pending_sinks:
                try:
                    sink.abort()
                except Exception:
                    pass
            raise
        return Response(parts=parts)

    def close(self) -> None:
        try:
            self.reader.sock.close()
        except OSError:
            pass


def quote_mailbox(value: str) -> str:
    if "\r" in value or "\n" in value or "\x00" in value:
        raise ValueError("mailbox name contains a forbidden control character")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("non-ASCII mailbox names are not supported by this collector") from exc
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def quote_string(value: str) -> str:
    if "\r" in value or "\n" in value or "\x00" in value:
        raise ValueError("argument contains a forbidden control character")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def parse_uid_set(text: str) -> tuple[set[int], bool]:
    """Parse an IMAP sequence/UID set.  Returns (uids, saw_star)."""
    uids: set[int] = set()
    saw_star = False
    for piece in text.split(","):
        piece = piece.strip()
        if not piece:
            continue
        if ":" in piece:
            lo_s, hi_s = piece.split(":", 1)
            if lo_s == "*" or hi_s == "*":
                saw_star = True
                continue
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            uids.update(range(lo, hi + 1))
        else:
            if piece == "*":
                saw_star = True
                continue
            uids.add(int(piece))
    return uids, saw_star


def format_uid_set(uids: Iterable[int]) -> str:
    ordered = sorted(set(uids))
    if not ordered:
        return ""
    ranges: list[str] = []
    start = prev = ordered[0]
    for uid in ordered[1:]:
        if uid == prev + 1:
            prev = uid
            continue
        ranges.append(str(start) if start == prev else f"{start}:{prev}")
        start = prev = uid
    ranges.append(str(start) if start == prev else f"{start}:{prev}")
    return ",".join(ranges)


class Connection:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        tls: str,
        timeout: float,
        verify_tls: bool,
        spool_dir: Path,
        literal_observer: Callable[[int, list[bytes | LiteralRef]], LiteralSink | None] | None = None,
    ):
        self.host = host
        self.port = port
        self.tls = tls
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.spool_dir = spool_dir
        self._literal_observer = literal_observer
        self._tag_counter = 0
        self.sock: socket.socket | None = None
        self.reader: _Reader | None = None
        self.parser: ResponseParser | None = None
        self.greeting: Response | None = None

    # -- transport -----------------------------------------------------
    def open(self) -> Response:
        last: Exception | None = None
        for attempt in range(2):
            try:
                self._open_socket()
                break
            except OSError as exc:
                last = exc
                time.sleep(0.05)
        else:
            raise ConnectionLost(f"cannot connect to {self.host}:{self.port}: {last}")
        assert self.reader is not None and self.parser is not None
        greeting = self.parser.next_response()
        first = greeting.first
        if not first.startswith(b"*") or b"OK" not in first[:32].upper():
            self.close()
            if b"BYE" in greeting.first.upper():
                raise ConnectionLost(f"server rejected greeting: {greeting.head_text()}")
            raise ProtocolError(f"unexpected greeting: {greeting.head_text()}")
        self.greeting = greeting
        return greeting

    def _open_socket(self) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.tls == "ssl":
            context = ssl.create_default_context()
            if not self.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw, server_hostname=self.host)
        else:
            sock = raw
        self.sock = sock
        self.reader = _Reader(sock, self.timeout)
        self.parser = ResponseParser(self.reader, self._literal_sink)

    def _literal_sink(self, size: int, parts: list[bytes | LiteralRef]) -> LiteralSink:
        if self._literal_observer is not None:
            chosen = self._literal_observer(size, parts)
            if chosen is not None:
                return chosen
        head = b"".join(p for p in parts if isinstance(p, bytes))
        if b"BODY[" in head.upper():
            return FileLiteralSink(size, self.spool_dir)
        return DigestSink(size)

    def starttls(self) -> None:
        if self.tls != "starttls":
            return
        self.command("STARTTLS", [])
        assert self.sock is not None
        context = ssl.create_default_context()
        if not self.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(self.sock, server_hostname=self.host)
        self.sock = sock
        self.reader = _Reader(sock, self.timeout)
        self.parser = ResponseParser(self.reader, self._literal_sink)

    def close(self) -> None:
        if self.parser is not None:
            self.parser.close()
        self.sock = None

    # -- commands ------------------------------------------------------
    def next_tag(self) -> str:
        self._tag_counter += 1
        return f"A{self._tag_counter:04d}"

    def send(self, command: str, args: list[str] | None = None) -> str:
        tag = self.next_tag()
        line = tag + " " + command
        if args:
            line += " " + " ".join(args)
        if "\r" in line or "\n" in line:
            raise ValueError("refusing to send CR/LF in a command line")
        assert self.sock is not None
        try:
            self.sock.sendall(line.encode("ascii") + b"\r\n")
        except OSError as exc:
            raise ConnectionLost(f"send failed: {exc}") from exc
        return tag

    def read_until_tag(
        self,
        tag: str,
        handler: Callable[[Response], None] | None = None,
        *,
        command_name: str = "command",
    ) -> Response:
        assert self.parser is not None
        while True:
            resp = self.parser.next_response()
            if resp.is_tagged():
                got = resp.tagged_tag()
                if got != tag:
                    raise ProtocolError(
                        f"tag mismatch: waiting for {tag}, got {got}: {resp.head_text()}"
                    )
                status = (resp.tagged_status() or "").upper()
                if status not in {"OK", "NO", "BAD"}:
                    raise ProtocolError(f"unrecognised tagged status: {resp.head_text()}")
                return resp
            if handler is not None:
                handler(resp)

    def command(
        self,
        command: str,
        args: list[str] | None = None,
        handler: Callable[[Response], None] | None = None,
    ) -> Response:
        tag = self.send(command, args)
        return self.read_until_tag(tag, handler, command_name=command)

    def login(self, user: str, password: str) -> Response:
        # Never include this command in diagnostics: the password is in it.
        resp = self.command("LOGIN", [quote_string(user), quote_string(password)])
        if resp.tagged_status() != "OK":
            raise AuthError(f"authentication rejected: {resp.tagged_text()}")
        return resp

    def capability(self) -> set[str]:
        caps: set[str] = set()
        resp = self.command("CAPABILITY", [], lambda r: caps.update(self._caps_from(r)))
        caps.update(self._caps_from(resp))
        return caps

    @staticmethod
    def _caps_from(resp: Response) -> set[str]:
        out: set[str] = set()
        toks = resp.tokens()
        if resp.first.upper().startswith(b"* CAPABILITY"):
            out.update(tok.upper() for tok in toks[2:])
        match = re.search(r"\[CAPABILITY\s+([^\]]+)\]", resp.head_text(), re.I)
        if match:
            out.update(tok.upper() for tok in match.group(1).split())
        return out


def open_connection(
    *,
    host: str,
    port: int,
    tls: str,
    timeout: float,
    verify_tls: bool,
    spool_dir: Path,
    literal_observer: Callable[[int, list[bytes | LiteralRef]], LiteralSink | None] | None = None,
) -> Connection:
    conn = Connection(
        host,
        port,
        tls=tls,
        timeout=timeout,
        verify_tls=verify_tls,
        spool_dir=spool_dir,
        literal_observer=literal_observer,
    )
    conn.open()
    if tls == "starttls":
        conn.starttls()
    return conn
