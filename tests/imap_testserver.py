"""A scriptable, real-TCP IMAP server used only by the acceptance suite.

The collector never imports this module.  Tests connect over a real loopback
socket so framing, partial fetches and mid-literal disconnects travel through
the same code path as a production server.

Behaviour is driven by :class:`Hook` objects that run inside the server thread
at defined points and may mutate mailbox state (emitting the matching untagged
responses), or drop the connection mid-literal.
"""

from __future__ import annotations

import hashlib
import re
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

CRLF = b"\r\n"


@dataclass
class Message:
    uid: int
    body: bytes
    flags: list[str] = field(default_factory=lambda: ["\\Seen"])
    modseq: int = 1
    internaldate: str = "01-Jan-2024 00:00:00 +0000"


@dataclass
class Hook:
    # before_select | after_select | before_search | before_fetch |
    # after_body | before_command
    trigger: str
    action: Callable[["Handler"], None]
    uid: int | None = None
    once: bool = True


@dataclass
class State:
    mailbox: str = "INBOX"
    uidvalidity: int = 1000
    uidnext: int = 1
    highestmodseq: int = 0
    messages: dict[int, Message] = field(default_factory=dict)
    tombstones: list[tuple[int, int]] = field(default_factory=list)
    capabilities: set[str] = field(
        default_factory=lambda: {"IMAP4rev1", "CONDSTORE", "QRESYNC"}
    )
    nomodseq: bool = False
    hooks: list[Hook] = field(default_factory=list)
    log: list[dict] = field(default_factory=list)
    lock: threading.RLock = field(default_factory=threading.RLock)
    user: str = "archiver"
    password: str = "s3cret-for-tests"
    deny_login: bool = False
    suppress_fetch: set[int] = field(default_factory=set)
    # (uid, nth body fetch for that uid, bytes to send) -- the connection is
    # cut after exactly `bytes` of the advertised literal.
    drop_body: list[tuple[int, int, int]] = field(default_factory=list)
    body_fetches: dict[int, int] = field(default_factory=dict)

    def add(self, body: bytes, uid: int | None = None, flags: list[str] | None = None) -> int:
        with self.lock:
            if uid is None:
                uid = self.uidnext
            self.uidnext = max(self.uidnext, uid + 1)
            self.messages[uid] = Message(
                uid=uid,
                body=bytes(body),
                flags=list(flags if flags is not None else ["\\Seen"]),
                modseq=self.bump_modseq(),
            )
            return uid

    def bump_modseq(self) -> int:
        self.highestmodseq += 1
        return self.highestmodseq

    def remove(self, uid: int) -> bool:
        with self.lock:
            if uid in self.messages:
                del self.messages[uid]
                self.tombstones.append((uid, self.bump_modseq()))
                return True
            return False

    def set_uidvalidity(self, value: int) -> None:
        with self.lock:
            self.uidvalidity = value

    def reset_mailbox(self, uidvalidity: int) -> None:
        with self.lock:
            self.messages.clear()
            self.tombstones.clear()
            self.uidvalidity = uidvalidity
            self.uidnext = 1
            self.highestmodseq = 0


class _DropConnection(Exception):
    pass


class Handler(socketserver.StreamRequestHandler):
    server: "ImapServer"

    def setup(self) -> None:
        super().setup()
        self.state = self.server.state
        self.conn_id = self.server.next_conn_id()
        self.selected = False
        self.qresync_on = False
        self.closed = False
        self.pending_drop: int | None = None
        self.queued_untagged: list[str] = []

    # -- plumbing ------------------------------------------------------
    def handle(self) -> None:
        self.server.active += 1
        try:
            self.emit("* OK [CAPABILITY " + " ".join(sorted(self.state.capabilities)) + "] test server ready")
            while not self.closed:
                line = self.rfile.readline()
                if not line or not line.endswith(CRLF):
                    break
                if self.dispatch(line[:-2].decode("latin-1")):
                    break
        except (_DropConnection, BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.server.active -= 1
            try:
                self.request.close()
            except OSError:
                pass

    def emit(self, text: str) -> None:
        target = self.request
        self.server.send(target, text.encode("latin-1") + CRLF)

    def dispatch_queued(self) -> None:
        queued = [t for t in self.queued_untagged if t.startswith("* ")]
        self.queued_untagged.clear()
        for text in queued:
            self.emit(text)

    def emit_bytes(self, data: bytes) -> None:
        self.server.send(self.request, data)

    def record(self, kind: str, **kw) -> None:
        entry = {"conn": self.conn_id, "kind": kind, "t": time.time()}
        entry.update(kw)
        with self.state.lock:
            self.state.log.append(entry)

    def hard_close(self) -> None:
        self.closed = True
        try:
            self.request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.request.close()
        except OSError:
            pass
        raise _DropConnection()

    # -- hooks ---------------------------------------------------------
    def run_hooks(self, trigger: str, uid: int | None = None) -> None:
        with self.state.lock:
            pending = [
                h
                for h in self.state.hooks
                if h.trigger == trigger and (h.uid is None or h.uid == uid)
            ]
            for hook in pending:
                if hook.once:
                    self.state.hooks.remove(hook)
        for hook in pending:
            hook.action(self)

    # -- mutations used by hooks --------------------------------------
    def add_message(
        self,
        body: bytes,
        uid: int | None = None,
        flags: list[str] | None = None,
        announce: bool = False,
    ) -> int:
        uid = self.state.add(body, uid=uid, flags=flags)
        self.record(
            "add",
            uid=uid,
            length=len(body),
            sha256=hashlib.sha256(body).hexdigest(),
        )
        if announce and self.selected:
            with self.state.lock:
                self.emit(f"* {len(self.state.messages)} EXISTS")
        return uid

    def expunge(self, uid: int, notify: bool = True) -> None:
        with self.state.lock:
            keys = sorted(self.state.messages)
            seq = keys.index(uid) + 1 if uid in keys else None
            removed = self.state.remove(uid)
        self.record("expunge", uid=uid, ok=removed, seq=seq)
        if not removed or not notify or not self.selected:
            return
        if self.qresync_on:
            self.emit(f"* VANISHED {uid}")
        elif seq is not None:
            self.server.write_untagged(self.request, f"* {seq} EXPUNGE")

    def set_flags(self, uid: int, flags: list[str], unsolicited: bool = True) -> None:
        with self.state.lock:
            msg = self.state.messages.get(uid)
            if msg is None:
                return
            msg.flags = list(flags)
            msg.modseq = self.state.bump_modseq()
            modseq = msg.modseq
            keys = sorted(self.state.messages)
            seq = keys.index(uid) + 1
        self.record("flags", uid=uid, flags=list(flags), modseq=modseq)
        if unsolicited and self.selected:
            self.emit(
                f"* {seq} FETCH (UID {uid} FLAGS ({' '.join(flags)}) MODSEQ ({modseq}))"
            )

    # -- command dispatch ---------------------------------------------
    def dispatch(self, text: str) -> bool:
        parts = text.split(" ", 2)
        if len(parts) < 2 or not parts[0]:
            self.emit("* BAD malformed command")
            return False
        tag, command = parts[0], parts[1].upper()
        args = parts[2] if len(parts) > 2 else ""
        if command == "LOGIN":
            # Never retain the test password in the server log.
            self.record("cmd", tag=tag, command=command, args="<redacted>")
        else:
            self.record("cmd", tag=tag, command=command, args=args[:400])
        handler = getattr(self, "cmd_" + command.lower(), None)
        if handler is None:
            self.emit(f"{tag} BAD command not supported by test server")
            return False
        return bool(handler(tag, args))

    def cmd_capability(self, tag: str, args: str) -> bool:
        self.emit("* CAPABILITY " + " ".join(sorted(self.state.capabilities)))
        self.emit(f"{tag} OK CAPABILITY completed")
        return False

    def cmd_noop(self, tag: str, args: str) -> bool:
        self.run_hooks("before_command", uid=None)
        self.emit(f"{tag} OK NOOP completed")
        return False

    def cmd_logout(self, tag: str, args: str) -> bool:
        self.emit("* BYE logging out")
        self.emit(f"{tag} OK LOGOUT completed")
        return True

    def cmd_login(self, tag: str, args: str) -> bool:
        user, password = _unquote_pair(args)
        if self.state.deny_login or (
            user != self.state.user or password != self.state.password
        ):
            self.record("auth", ok=False)
            self.emit(f"{tag} NO [AUTHENTICATIONFAILED] invalid credentials")
            return False
        self.record("auth", ok=True)
        self.emit(f"{tag} OK LOGIN completed")
        return False

    def cmd_enable(self, tag: str, args: str) -> bool:
        if "QRESYNC" in args.upper() and "QRESYNC" in self.state.capabilities:
            self.qresync_on = True
            self.emit("* ENABLED QRESYNC")
        self.emit(f"{tag} OK ENABLE completed")
        return False

    def cmd_status(self, tag: str, args: str) -> bool:
        with self.state.lock:
            values = {
                "MESSAGES": len(self.state.messages),
                "UIDNEXT": self.state.uidnext,
                "UIDVALIDITY": self.state.uidvalidity,
                "HIGHESTMODSEQ": self.state.highestmodseq,
                "UNSEEN": 0,
            }
        wanted = re.findall(r"[A-Za-z]+", args.split("(", 1)[-1]) if "(" in args else []
        if not wanted:
            wanted = ["MESSAGES", "UIDNEXT", "UIDVALIDITY"]
        parts = [f"{name.upper()} {values.get(name.upper(), 0)}" for name in wanted]
        self.emit('* STATUS "' + self.state.mailbox + '" (' + " ".join(parts) + ")")
        self.emit(f"{tag} OK STATUS completed")
        return False

    def cmd_examine(self, tag: str, args: str) -> bool:
        return self.do_select(tag, read_only=True)

    def cmd_select(self, tag: str, args: str) -> bool:
        return self.do_select(tag, read_only=False)

    def do_select(self, tag: str, read_only: bool) -> bool:
        self.run_hooks("before_select")
        with self.state.lock:
            count = len(self.state.messages)
            uidvalidity = self.state.uidvalidity
            uidnext = self.state.uidnext
            modseq = self.state.highestmodseq
        self.emit(f"* {count} EXISTS")
        self.emit("* 0 RECENT")
        self.emit("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)")
        self.emit("* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] flags")
        self.emit(f"* OK [UIDVALIDITY {uidvalidity}] UIDs valid")
        self.emit(f"* OK [UIDNEXT {uidnext}] predicted next UID")
        self.selected = True
        if self.state.nomodseq:
            mode = "READ-ONLY" if read_only else "READ-WRITE"
            self.emit(f"* OK [NOMODSEQ] no modseq")
            self.emit(f"{tag} OK [{mode}] selected")
        else:
            if "CONDSTORE" in self.state.capabilities:
                self.emit(f"* OK [HIGHESTMODSEQ {modseq}] highest")
            self.run_hooks("after_select")
            mode = "READ-ONLY" if read_only else "READ-WRITE"
            self.emit(f"{tag} OK [{mode}] selected")
        return False

    # -- UID ----------------------------------------------------------
    def cmd_uid(self, tag: str, args: str) -> bool:
        if not self.selected:
            self.emit(f"{tag} BAD no mailbox selected")
            return False
        sub, _, rest = args.partition(" ")
        sub = sub.upper()
        if sub == "SEARCH":
            return self.uid_search(tag, rest)
        if sub == "FETCH":
            return self.uid_fetch(tag, rest)
        if sub in {"STORE", "EXPUNGE", "COPY", "MOVE"}:
            self.record("mutation_attempt", command="UID " + sub)
            self.emit(f"{tag} NO this archival test server forbids mutations")
            return False
        self.emit(f"{tag} BAD unsupported UID subcommand")
        return False

    def uid_search(self, tag: str, args: str) -> bool:
        self.run_hooks("before_search")
        with self.state.lock:
            uids = sorted(self.state.messages)
            messages = self.state.messages
            match = re.search(r"UID\s+(\d+|\*):(\d+|\*)", args, re.I)
            if match:
                lo = 1 if match.group(1) == "*" else int(match.group(1))
                hi = len(uids) if match.group(2) == "*" else int(match.group(2))
                lo, hi = min(lo, hi), max(lo, hi)
                uids = [u for u in uids if lo <= u <= hi]
            m = re.search(r"MODSEQ\s+\(?(\d+)\)?", args, re.I)
            if m:
                floor = int(m.group(1))
                uids = [u for u in uids if messages[u].modseq >= floor]
            if re.search(r"\bDELETED\b", args, re.I):
                uids = [u for u in uids if "\\Deleted" in messages[u].flags]
        self.emit("* SEARCH " + " ".join(str(u) for u in uids))
        self.emit(f"{tag} OK SEARCH completed")
        return False

    def uid_fetch(self, tag: str, args: str) -> bool:
        match = re.match(r"(\S+)\s+(.*)$", args.strip(), re.S)
        if not match:
            self.emit(f"{tag} BAD malformed UID FETCH")
            return False
        uid_spec, rest = match.group(1), match.group(2).strip()
        if ":" in uid_spec:
            spec_lo, spec_hi = (int(x) for x in uid_spec.split(":", 1))
            wanted = {u for u in self.state.messages if spec_lo <= u <= spec_hi}
        else:
            wanted = {int(uid_spec)}
        if len(wanted) != 1:
            self.run_hooks("before_fetch", uid=None)
        else:
            uid = next(iter(wanted))
            self.run_hooks("before_fetch", uid=uid)

        items, modifier = _split_fetch_args(rest)
        bare = _strip_brackets(items)
        upper = bare.upper()
        changedsince = modifier.get("changedsince")
        wants_vanished = modifier.get("vanished", False)
        partial = re.search(r"<(\d+)\.(\d+)>", items, re.S)

        with self.state.lock:
            if len(wanted) == 1 and next(iter(wanted)) in self.state.suppress_fetch:
                # Answer OK but omit the FETCH data entirely: absence of a
                # reply must never be read as deletion by the client.
                self.record("suppressed_fetch", uid=next(iter(wanted)))
                self.emit(f"{tag} OK FETCH completed")
                return False
            present = [u for u in sorted(wanted) if u in self.state.messages]
            vanished = []
            if changedsince is not None:
                floor = changedsince
                if wants_vanished:
                    vanished = [
                        u for (u, m) in self.state.tombstones if m >= floor and u not in self.state.messages
                    ]
        if vanished:
            self.emit("* VANISHED (EARLIER) " + _format_uid_set(vanished))

        # Untagged EXPUNGE lines produced by hooks are sent here so that they
        # precede any body literal of this FETCH.

        wants_body = "BODY" in upper and "[" in items
        for uid in present:
            with self.state.lock:
                message = self.state.messages.get(uid)
                if message is None:
                    continue
                if changedsince is not None and message.modseq < changedsince:
                    continue
                keys = sorted(self.state.messages)
                seq = keys.index(uid) + 1
                body = message.body
                flags = list(message.flags)
                modseq = message.modseq
                size = len(body)

            fields = []
            if re.search(r"\bUID\b", upper):
                fields.append(f"UID {uid}")
            if "FLAGS" in upper:
                fields.append("FLAGS (" + " ".join(flags) + ")")
            if "RFC822.SIZE" in upper:
                fields.append(f"RFC822.SIZE {size}")
            if "MODSEQ" in upper:
                fields.append(f"MODSEQ ({modseq})")

            if not wants_body:
                self.emit(f"* {seq} FETCH (" + " ".join(fields) + ")")
                continue
            if len(present) != 1:
                self.emit(f"{tag} BAD body fetch must name a single UID")
                return False
            section, start, count = _parse_partial(items, size)
            if section not in {"", "TEXT"}:
                self.emit(f"{tag} BAD only BODY[] is scripted")
                return False
            piece = body[start:] if count is None else body[start:start + count]
            prefix = f"* {seq} FETCH (" + (" ".join(fields) + " " if fields else "")
            prefix += f"BODY[]<{start}> {{{len(piece)}}}"
            self.record("fetch_body", uid=uid, origin=start, length=len(piece))
            self.emit_bytes(prefix.encode("latin-1") + CRLF)
            with self.state.lock:
                occurrence = self.state.body_fetches.get(uid, 0) + 1
                self.state.body_fetches[uid] = occurrence
                drop_bytes = None
                for index, (duid, nth, count) in enumerate(self.state.drop_body):
                    if duid == uid and nth == occurrence:
                        drop_bytes = count
                        self.state.drop_body.pop(index)
                        break
            if drop_bytes is not None:
                sent = min(drop_bytes, len(piece))
                self.emit_bytes(piece[:sent])
                self.record("literal_drop", uid=uid, sent=sent, declared=len(piece))
                self.hard_close()
            self.emit_bytes(piece + b")" + CRLF)
            self.run_hooks("after_body", uid=uid)
            with self.state.lock:
                pending = self.pending_drop
                self.pending_drop = None
            if pending is not None:
                pass
        self.emit(f"{tag} OK FETCH completed")
        return False

    # -- forbidden / unknown ------------------------------------------
    def cmd_store(self, tag: str, args: str) -> bool:
        self.record("mutation_attempt", command="STORE")
        self.emit(f"{tag} NO STORE forbidden")
        return False

    def cmd_expunge(self, tag: str, args: str) -> bool:
        self.record("mutation_attempt", command="EXPUNGE")
        self.emit(f"{tag} NO EXPUNGE forbidden")
        return False

    def cmd_starttls(self, tag: str, args: str) -> bool:
        self.emit(f"{tag} NO STARTTLS not supported by the test server")
        return False


def _parse_uid_set(spec: str) -> set[int]:
    out: set[int] = set()
    for piece in spec.split(","):
        piece = piece.strip()
        if not piece:
            continue
        if ":" in piece:
            lo_s, hi_s = piece.split(":", 1)
            lo, hi = int(lo_s), int(hi_s)
            out.update(range(min(lo, hi), max(lo, hi) + 1))
        else:
            out.add(int(piece))
    return out


def _format_uid_set(values: list[int]) -> str:
    ordered = sorted(set(values))
    if not ordered:
        return ""
    out: list[str] = []
    start = prev = ordered[0]
    for uid in ordered[1:]:
        if uid == prev + 1:
            prev = uid
            continue
        out.append(str(start) if start == prev else f"{start}:{prev}")
        start = prev = uid
    out.append(str(start) if start == prev else f"{start}:{prev}")
    return ",".join(out)


def _split_fetch_args(rest: str) -> tuple[str, dict]:
    """Split ``(ITEMS) (MODIFIER)`` into item text and modifier values."""
    rest = rest.strip()
    if rest.startswith("("):
        depth = 0
        end = None
        for index, ch in enumerate(rest):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        if end is None:
            return rest, {}
        items = rest[1:end]
        tail = rest[end + 1:].strip()
    else:
        parts = rest.split(" ", 1)
        items = parts[0]
        tail = parts[1].strip() if len(parts) > 1 else ""
    modifier: dict = {}
    if tail:
        m = re.search(r"CHANGEDSINCE\s+(\d+)", tail, re.I)
        if m:
            modifier["changedsince"] = int(m.group(1))
        if re.search(r"\bVANISHED\b", tail, re.I):
            modifier["vanished"] = True
    return items, modifier


def _strip_brackets(items: str) -> str:
    """Remove ``[...]`` sections so keywords inside them are not mistaken."""
    out = []
    depth = 0
    for ch in items:
        if ch == "[":
            depth += 1
            continue
        if ch == "]":
            depth = max(0, depth - 1)
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def _parse_partial(items: str, size: int) -> tuple[str, int, int | None]:
    m = re.search(r"BODY(?:\.PEEK)?\[([^\]]*)\](?:<(\d+)\.(\d+)>)?", items, re.I | re.S)
    if not m:
        return "", 0, None
    section = m.group(1).strip().upper()
    if m.group(2) is None:
        return section, 0, None
    return section, int(m.group(2)), int(m.group(3))


def _unquote_pair(args: str) -> tuple[str, str]:
    values = re.findall(r'"((?:[^"\\]|\\.)*)"', args)
    unescaped = [v.replace('\\"', '"').replace("\\\\", "\\") for v in values]
    while len(unescaped) < 2:
        unescaped.append("")
    return unescaped[0], unescaped[1]


class ImapServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, state: State, host: str = "127.0.0.1", port: int = 0):
        self.state = state
        self.active = 0
        self._conn_counter = 0
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self.thread: threading.Thread | None = None
        super().__init__((host, port), Handler)

    def next_conn_id(self) -> int:
        with self._lock:
            self._conn_counter += 1
            return self._conn_counter

    def send(self, sock: socket.socket, data: bytes) -> None:
        with self._send_lock:
            sock.sendall(data)

    def write_untagged(self, sock: socket.socket, text: str) -> None:
        self.send(sock, text.encode("latin-1") + CRLF)

    @property
    def host(self) -> str:
        return self.server_address[0]

    @property
    def port(self) -> int:
        return self.server_address[1]

    def start(self) -> "ImapServer":
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)

    def __enter__(self) -> "ImapServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
