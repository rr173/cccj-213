"""Parsing of IMAP response structures (not message content)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .protocol import LiteralRef, Response

_ATOM_STOP = b' \t()"'


class ParseError(Exception):
    pass


@dataclass
class Atom:
    value: str
    quoted: bool = False

    def __str__(self) -> str:
        return self.value


def tokenize(resp: Response) -> list:
    """Turn a response's parts into structural tokens.

    Returns a list containing ``"("``, ``")"``, :class:`Atom`,
    :class:`LiteralRef` and nested Python lists produced by grouping.
    Bracket sections such as ``BODY[HEADER.FIELDS (FROM TO)]`` are kept whole.
    """
    flat: list = []
    for part in resp.parts:
        if isinstance(part, LiteralRef):
            flat.append(part)
            continue
        i = 0
        n = len(part)
        while i < n:
            c = part[i : i + 1]
            if c in (b" ", b"\t", b"\r", b"\n"):
                i += 1
                continue
            if c == b"(" or c == b")":
                flat.append("(" if c == b"(" else ")")
                i += 1
                continue
            if c == b'"':
                value = bytearray()
                i += 1
                while i < n:
                    ch = part[i : i + 1]
                    if ch == b"\\" and i + 1 < n:
                        value.extend(part[i + 1 : i + 2])
                        i += 2
                        continue
                    if ch == b'"':
                        i += 1
                        break
                    value.extend(ch)
                    i += 1
                else:
                    raise ParseError("unterminated quoted string")
                flat.append(Atom(value.decode("utf-8", "replace"), quoted=True))
                continue
            # atom; bracket sections may contain spaces and parentheses
            start = i
            depth = 0
            while i < n:
                ch = part[i : i + 1]
                if depth == 0 and ch in (b" ", b"\t", b"\r", b"\n", b"(", b")"):
                    break
                if ch == b"[":
                    depth += 1
                elif ch == b"]" and depth > 0:
                    depth -= 1
                i += 1
            flat.append(Atom(part[start:i].decode("latin-1")))
    return _group(flat)


def _group(flat: list) -> list:
    root: list = []
    stack = [root]
    for tok in flat:
        if tok == "(":
            new: list = []
            stack[-1].append(new)
            stack.append(new)
        elif tok == ")":
            if len(stack) == 1:
                raise ParseError("unbalanced ')'")
            stack.pop()
        else:
            stack[-1].append(tok)
    if len(stack) != 1:
        raise ParseError("unbalanced '('")
    return root


def atom_value(tok) -> str:
    if isinstance(tok, Atom):
        return tok.value
    if isinstance(tok, LiteralRef):
        raise ParseError("expected atom, got literal")
    raise ParseError(f"expected atom, got {type(tok).__name__}")


def is_fetch(resp: Response) -> bool:
    toks = resp.tokens()
    return len(toks) >= 3 and toks[0] == "*" and toks[1].isdigit() and toks[2].upper() == "FETCH"


def response_kind(resp: Response) -> str | None:
    """Untagged response keyword, e.g. ``EXISTS``, ``FETCH``, ``OK``."""
    toks = resp.tokens()
    if len(toks) < 2 or toks[0] != "*":
        return None
    second = toks[1].upper()
    if second.isdigit() and len(toks) >= 3:
        return toks[2].upper()
    return second


def find_key(items: list, key: str):
    for i in range(0, len(items) - 1, 2):
        k = items[i]
        if isinstance(k, Atom) and k.value.upper() == key.upper():
            return items[i + 1]
    return None


@dataclass
class FetchData:
    seq: int
    uid: int | None
    flags: list[str] | None
    modseq: int | None
    internal_date: str | None
    bodies: list[tuple[str, int, LiteralRef]] = field(default_factory=list)
    size: int | None = None
    raw_keys: list[str] = field(default_factory=list)

    def body(self, section: str = "") -> tuple[int, LiteralRef] | None:
        for key, origin, lit in self.bodies:
            if key.upper() == section.upper():
                return origin, lit
        return None


def parse_fetch(resp: Response) -> FetchData:
    tree = tokenize(resp)
    if len(tree) < 4 or not isinstance(tree[3], list):
        raise ParseError("malformed FETCH response")
    seq = int(atom_value(tree[1]))
    items = tree[3]
    uid = None
    flags = None
    modseq = None
    internal = None
    size = None
    bodies: list[tuple[str, int, LiteralRef]] = []
    raw_keys: list[str] = []
    for i in range(0, len(items) - 1, 2):
        key = atom_value(items[i])
        value = items[i + 1]
        upper = key.upper()
        raw_keys.append(key)
        if upper == "UID":
            uid = int(atom_value(value))
        elif upper == "FLAGS":
            flags = []
            if isinstance(value, list):
                for tok in value:
                    flags.append(atom_value(tok))
        elif upper == "MODSEQ":
            if isinstance(value, list) and value:
                modseq = int(atom_value(value[0]))
            else:
                modseq = int(atom_value(value))
        elif upper == "INTERNALDATE":
            internal = atom_value(value)
        elif upper == "RFC822.SIZE":
            size = int(atom_value(value))
        elif upper.startswith("BODY[") or upper.startswith("BODY."):
            if not isinstance(value, LiteralRef):
                continue
            section, origin = parse_section_key(key)
            bodies.append((section, origin, value))
    return FetchData(
        seq=seq,
        uid=uid,
        flags=flags,
        modseq=modseq,
        internal_date=internal,
        bodies=bodies,
        size=size,
        raw_keys=raw_keys,
    )


def parse_section_key(key: str) -> tuple[str, int]:
    """``BODY[HEADER]<0>`` -> ("HEADER", 0); ``BODY[]`` -> ("", 0)."""
    origin = 0
    base = key
    m = re.search(r"<(\d+)>$", key)
    if m:
        origin = int(m.group(1))
        base = key[: m.start()]
    if "." in base.split("[", 1)[0]:
        base = "BODY" + base.split(".", 1)[1]
    section = ""
    m2 = re.search(r"\[(.*)\]", base, re.S)
    if m2:
        section = m2.group(1).strip()
    return section, origin


_RESPONSE_CODE_RE = re.compile(r"\[([A-Za-z0-9._-]+)(?:\s+([^\]]*))?\]")


@dataclass
class SelectedInfo:
    exists: int | None = None
    recent: int | None = None
    uidvalidity: int | None = None
    uidnext: int | None = None
    highestmodseq: int | None = None
    nomodseq: bool = False
    read_only: bool = False
    permanentflags: list[str] = field(default_factory=list)
    vanished: set[int] = field(default_factory=set)


def parse_vanished(resp: Response) -> set[int]:
    toks = resp.tokens()
    if len(toks) < 3 or toks[0] != "*" or toks[1].upper() != "VANISHED":
        return set()
    index = 2
    if index < len(toks) and toks[index].upper() == "(EARLIER)":
        index += 1
    out: set[int] = set()
    if index >= len(toks):
        return out
    for piece in toks[index].split(","):
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


def parse_select_greeting(resp: Response, info: SelectedInfo) -> None:
    kind = response_kind(resp)
    text = resp.head_text()
    if kind == "VANISHED":
        # QRESYNC may report deletions during the SELECT response itself.
        info.vanished |= parse_vanished(resp)
        return
    if kind == "EXISTS":
        info.exists = int(resp.tokens()[1])
    elif kind == "RECENT":
        info.recent = int(resp.tokens()[1])
    elif kind == "OK":
        for m in _RESPONSE_CODE_RE.finditer(text):
            code = m.group(1).upper()
            arg = (m.group(2) or "").strip()
            if code == "UIDVALIDITY" and arg:
                info.uidvalidity = int(arg.split()[0])
            elif code == "UIDNEXT" and arg:
                info.uidnext = int(arg.split()[0])
            elif code == "HIGHESTMODSEQ" and arg:
                info.highestmodseq = int(arg.split()[0])
            elif code == "PERMANENTFLAGS":
                info.permanentflags = re.findall(r"\\?[A-Za-z0-9._-]+|\\.", arg)
            elif code == "READ-ONLY":
                info.read_only = True
    if "NOMODSEQ" in text.upper():
        info.nomodseq = True


def parse_status(resp: Response) -> tuple[str, dict[str, int]] | None:
    toks = resp.tokens()
    if len(toks) < 4 or toks[0] != "*" or toks[1].upper() != "STATUS":
        return None
    tree = tokenize(resp)
    if len(tree) < 4 or not isinstance(tree[3], list):
        return None
    name = atom_value(tree[2])
    values: dict[str, int] = {}
    items = tree[3]
    for i in range(0, len(items) - 1, 2):
        values[atom_value(items[i]).upper()] = int(atom_value(items[i + 1]))
    return name, values
