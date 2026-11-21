"""The read-only archival round state machine."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .archive import (
    AssemblyError,
    ConflictError,
    Layout,
    assemble_message,
    sha256_file,
)
from .config import Config
from .parse import (
    FetchData,
    ParseError,
    is_fetch,
    parse_fetch,
    parse_status,
    parse_vanished,
)
from .protocol import (
    ConnectionLost,
    ImapError,
    LiteralRef,
    ProtocolError,
    Response,
    format_uid_set,
    quote_mailbox,
)
from .session import BodyContext, CollectorError, Selection, Session
from .store import Store

_HIGHESTMODSEQ = re.compile(r"\[HIGHESTMODSEQ\s+([0-9]+)\]", re.I)


def _search_uids(resp: Response) -> set[int]:
    toks = resp.tokens()
    if len(toks) < 2 or toks[0] != "*" or toks[1].upper() != "SEARCH":
        raise ProtocolError(f"unexpected SEARCH response: {resp.head_text()}")
    return {int(tok) for tok in toks[2:] if tok.isdigit()}


_vanished_uids = parse_vanished


@dataclass
class RoundResult:
    mailbox: str
    uidvalidity: int
    generation_id: int
    round_id: int
    status: str
    uidnext_at_round: int
    progress: int
    present: list[int]
    missing: list[int]
    complete: list[int]
    unresolved: list[int]
    conflict: list[int]
    expunged_complete: list[int]
    resumed: bool
    condstore: bool
    qresync: bool
    full_inventory: bool
    baseline: int | None
    highestmodseq: int | None
    error: str | None = None
    events: int = 0

    def as_dict(self) -> dict:
        return {
            "mailbox": self.mailbox,
            "uidvalidity": self.uidvalidity,
            "generation_id": self.generation_id,
            "round_id": self.round_id,
            "status": self.status,
            "uidnext_at_round": self.uidnext_at_round,
            "progress": self.progress,
            "present": self.present,
            "missing": self.missing,
            "complete": self.complete,
            "unresolved": self.unresolved,
            "conflict": self.conflict,
            "expunged_complete": self.expunged_complete,
            "resumed": self.resumed,
            "condstore": self.condstore,
            "qresync": self.qresync,
            "full_inventory": self.full_inventory,
            "baseline": self.baseline,
            "highestmodseq": self.highestmodseq,
            "error": self.error,
            "events": self.events,
        }


class Collector:
    """Runs (or resumes) exactly one round for the configured mailbox."""

    def __init__(self, config: Config, store: Store, layout: Layout):
        self.config = config
        self.store = store
        self.layout = layout
        self.session = Session(config, store)
        self.mailbox = config.mailbox
        self.mailbox_id = store.mailbox_id(config.mailbox)
        self.round_id: int | None = None
        self.generation_id: int | None = None
        self.uidvalidity: int | None = None
        self.bound: int = 1
        self.condstore = False
        self.qresync = False
        self.baseline: int | None = None
        self.final_highestmodseq: int | None = None
        self.full_inventory = True
        self.resumed = False
        self.selection: Selection | None = None
        self.present: set[int] = set()
        self.observed: set[int] = set()
        self.attempts: dict[int, int] = {}

    # -- event log -----------------------------------------------------
    def _commit_body_literals(
        self, uid: int, ctx: BodyContext, expected_origin: int
    ) -> None:
        """Publish fully read body literals that can be attributed to this UID.

        A literal becomes a part only when the response prefix named the
        requested UID (or omitted the UID entirely) and its origin equals the
        request.  A literal fully read before the connection died is still
        verified here, so nothing already received is thrown away.
        """
        assert self.generation_id is not None
        assert self.uidvalidity is not None
        if ctx.rejected:
            self._event(uid, "literal_rejected", ctx.reject_reason or "")
            for body in ctx.literals:
                if body.ref.path:
                    Path(body.ref.path).unlink(missing_ok=True)
            ctx.literals.clear()
            return
        row = self.store.message(self.generation_id, uid)
        if row is None:
            for body in ctx.literals:
                if body.ref.path:
                    Path(body.ref.path).unlink(missing_ok=True)
            ctx.literals.clear()
            return
        for body in ctx.literals:
            ref = body.ref
            if body.prefix_uid is None:
                # The response never named a UID, so these bytes cannot be
                # proven to belong to this message.  Never store them.
                if ref.path:
                    Path(ref.path).unlink(missing_ok=True)
                self._event(uid, "literal_unattributable", "response prefix had no UID")
                continue
            if body.prefix_uid != uid:
                if ref.path:
                    Path(ref.path).unlink(missing_ok=True)
                continue
            origin = (
                body.prefix_origin if body.prefix_origin is not None else expected_origin
            )
            if origin != expected_origin:
                if ref.path:
                    Path(ref.path).unlink(missing_ok=True)
                self._event(
                    uid,
                    "literal_origin_mismatch",
                    f"requested {expected_origin}, got {origin}",
                )
                continue
            if ref.size > ctx.max_size:
                if ref.path:
                    Path(ref.path).unlink(missing_ok=True)
                self._event(
                    uid,
                    "literal_oversize",
                    f"requested {ctx.max_size}, got {ref.size}",
                )
                continue
            self._store_part(uid, int(row["id"]), origin, ref)
        ctx.literals.clear()

    def _commit_early_literal(self, origin: int, ref: LiteralRef) -> None:
        """Record a verified block the moment its prefix proves its identity.

        The prefix already carried the requested UID and origin, so the bytes
        are kept even if the connection is lost before the tagged response.
        Bytes for a UID whose previous body was pinned (changed or incomplete)
        are discarded, so a later body can never be spliced together from
        different responses.
        """
        assert self.generation_id is not None
        ctx = self.body_context
        if ctx is None or ctx.rejected:
            return
        row = self.store.message(self.generation_id, ctx.uid)
        if row is None or (row["body_digest_pinned"] and not row["complete"]):
            if ref.path:
                Path(ref.path).unlink(missing_ok=True)
            return
        try:
            self._store_part(ctx.uid, int(row["id"]), origin, ref)
        except AssemblyError as exc:
            self._event(ctx.uid, "part_commit_error", str(exc)[:300])
            if ref.path:
                Path(ref.path).unlink(missing_ok=True)

    def _store_part(
        self, uid: int, message_id: int, origin: int, ref: LiteralRef
    ) -> None:
        assert self.generation_id is not None
        assert self.uidvalidity is not None
        if ref.path is None:
            self._event(uid, "literal_not_persisted", "literal consumed as a digest")
            return
        existing = self.store.part_by_origin(message_id, origin)
        if existing is not None:
            if existing["sha256"] == ref.sha256 and int(existing["length"]) == ref.size:
                Path(ref.path).unlink(missing_ok=True)
                return
            # Bytes at a verified offset changed under the same UID: keep the
            # original and never silently replace it.
            Path(ref.path).unlink(missing_ok=True)
            self._conflict(
                uid, f"stored part at origin {origin} differs from the server bytes"
            )
            return
        digest, length = sha256_file(Path(ref.path))
        if digest != ref.sha256 or length != ref.size:
            Path(ref.path).unlink(missing_ok=True)
            raise AssemblyError(f"UID {uid}: spool literal failed verification")
        target = self.layout.part_file(self.mailbox, self.uidvalidity, uid, origin)
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(ref.path, target)
        self.store.add_part(message_id, origin, length, digest, str(target))
        self._event(
            uid, "part_stored", f"origin={origin} length={length} sha256={digest}"
        )

    def _event(self, uid: int | None, kind: str, detail: str = "") -> None:
        if self.round_id is not None:
            self.store.add_event(self.round_id, uid, kind, detail)

    def _note_modseq(self, resp: Response) -> None:
        for match in _HIGHESTMODSEQ.finditer(resp.head_text()):
            value = int(match.group(1))
            if self.final_highestmodseq is None or value > self.final_highestmodseq:
                self.final_highestmodseq = value

    # -- entry point ---------------------------------------------------
    def run(self) -> RoundResult:
        try:
            self.session.connect()
        except ConnectionLost:
            raise
        except BaseException:
            self.session.close()
            raise
        try:
            return self._run()
        except ConnectionLost as exc:
            if self.round_id is not None:
                self.store.set_round_error(self.round_id, f"connection lost: {exc}")
                self._event(None, "round_interrupted", str(exc)[:500])
            raise
        finally:
            self.session.logout()

    def _run(self) -> RoundResult:
        caps = self.session.capability()
        qresync_enabled = False
        if "QRESYNC" in caps:
            try:
                resp = self.session.command("ENABLE", ["QRESYNC"])
                qresync_enabled = (resp.tagged_status() or "").upper() == "OK"
            except ImapError:
                qresync_enabled = False
            if qresync_enabled:
                caps = self.session.capability()

        selection = self.session.examine([], caps)
        self.selection = selection
        info = selection.info
        assert info.uidvalidity is not None
        if info.uidnext is None:
            raise CollectorError("server supplied no UIDNEXT; cannot fix a reception bound")
        self.uidvalidity = info.uidvalidity
        self.final_highestmodseq = info.highestmodseq
        generation = self.store.ensure_generation(self.mailbox_id, info.uidvalidity)
        self.generation_id = int(generation["id"])
        self.layout.ensure_generation(self.mailbox, info.uidvalidity)

        # A different UIDVALIDITY is a different generation: no UID ranges,
        # MODSEQ baselines or open rounds may leak across.
        for stale in self.store.stale_open_rounds(self.mailbox_id, self.generation_id):
            self.store.mark_round_stale(
                int(stale["id"]),
                "UIDVALIDITY changed; generation closed",
            )

        self.condstore = selection.condstore
        self.qresync = selection.qresync and qresync_enabled

        open_round = self.store.get_open_round(self.generation_id)
        if open_round is not None:
            self.resumed = True
            self.round_id = int(open_round["id"])
            self.bound = int(open_round["uidnext_at_round"])
            self.baseline = (
                int(open_round["highestmodseq_baseline"])
                if open_round["highestmodseq_baseline"] is not None
                else None
            )
            self.full_inventory = bool(open_round["full_inventory"])
            # A resumed round keeps its fixed bound even if UIDNEXT has grown.
            self._event(
                None,
                "resume",
                f"fixed bound {self.bound} from original round; "
                f"current uidnext {info.uidnext}",
            )
        else:
            self.baseline = self._validated_baseline()
            self.full_inventory = self.baseline is None
            self.bound = int(info.uidnext)
            row = self.store.start_round(
                self.mailbox_id,
                self.generation_id,
                self.bound,
                condstore=self.condstore,
                qresync=self.qresync,
                baseline=self.baseline,
                full_inventory=self.full_inventory,
            )
            self.round_id = int(row["id"])
            self._event(
                None,
                "start",
                f"uidnext={self.bound} condstore={self.condstore} "
                f"qresync={self.qresync} full_inventory={self.full_inventory} "
                f"baseline={self.baseline}",
            )

        self.store.set_round_mode(
            self.round_id,
            condstore=self.condstore,
            qresync=self.qresync,
            full=self.full_inventory,
        )
        self._event(
            None,
            "select",
            f"uidvalidity={self.uidvalidity} uidnext={info.uidnext} "
            f"highestmodseq={info.highestmodseq} "
            f"read_only={self.selection.read_only} caps={','.join(sorted(caps))}",
        )
        self.store.update_generation_seen(
            self.generation_id, int(info.uidnext), info.highestmodseq
        )
        if info.vanished:
            # Deletions announced in the SELECT response (QRESYNC) belong to
            # this generation and are explicit evidence.
            self._record_vanished({uid for uid in info.vanished if uid >= 1})

        # 1. Complete inventory of the fixed range.
        self.present = self._inventory("initial")
        for uid in sorted(self.present):
            self.store.ensure_message(self.generation_id, uid)

        # 2. Bodies.
        self._receive_phase()

        # 3. Catalogue refresh: flags, sizes and incremental VANISHED.
        self._refresh_metadata()

        # 4. Complete inventory again; nothing may be called missing before it.
        for attempt in range(3):
            final_present = self._inventory("final" if attempt == 0 else f"final_{attempt + 1}")
            self.present = final_present
            if not self._unsettled():
                break
            self._event(
                None,
                "extra_pass",
                "unsettled after inventory: " + format_uid_set(self._unsettled()),
            )
            self._receive_phase()
        else:
            final_present = self.present

        # 5. All observations settled: reconcile and only now commit progress.
        self.final_highestmodseq = self._final_highestmodseq()
        return self._reconcile(final_present)

    def _final_highestmodseq(self) -> int | None:
        """Best-effort accurate end-of-round HIGHESTMODSEQ for the baseline.

        An incremental baseline is only offered to a later round when the
        server itself reports the mailbox state; otherwise the previous value
        we observed is used only if no newer code arrived.
        """
        if not self.condstore:
            return self.final_highestmodseq
        reported: int | None = None

        def handler(resp: Response) -> None:
            self._note_modseq(resp)
            parsed = parse_status(resp)
            if parsed is not None and "HIGHESTMODSEQ" in parsed[1]:
                nonlocal reported
                reported = parsed[1]["HIGHESTMODSEQ"]

        try:
            resp = self.session.command(
                "STATUS",
                [quote_mailbox(self.mailbox), "(HIGHESTMODSEQ UIDNEXT)"],
                handler,
            )
        except ImapError as exc:
            self._event(None, "status_failed", str(exc)[:300])
            return self.final_highestmodseq
        if (resp.tagged_status() or "").upper() != "OK" or reported is None:
            return self.final_highestmodseq
        if self.final_highestmodseq is None or reported > self.final_highestmodseq:
            return reported
        return self.final_highestmodseq

    # -- baseline ------------------------------------------------------
    def _validated_baseline(self) -> int | None:
        """Return a provably usable CHANGEDSINCE baseline, else ``None``."""
        if not self.condstore:
            return None
        previous = self.store.last_complete_round(self.generation_id)
        if previous is None or previous["highestmodseq_at_end"] is None:
            return None
        baseline = int(previous["highestmodseq_at_end"])
        if self.selection is None or self.selection.info.highestmodseq is None:
            return None
        # The mailbox's current HIGHESTMODSEQ can never be below a previously
        # observed one; if it is, the server's MODSEQ history is not trustworthy
        # and an incremental pass cannot be proven valid.
        if self.selection.info.highestmodseq < baseline:
            return None
        return baseline

    # -- inventory -----------------------------------------------------
    def _inventory(self, label: str) -> set[int]:
        if self.bound <= 1:
            self._event(None, f"inventory_{label}", "range empty (uidnext=1)")
            return set()
        found: set[int] = set()
        seen = False

        def handler(resp: Response) -> None:
            nonlocal seen
            self._note_modseq(resp)
            toks = resp.tokens()
            if toks[:2] == ["*", "SEARCH"]:
                found.update(_search_uids(resp))
                seen = True
                return
            if len(toks) >= 3 and toks[0] == "*" and toks[2].upper() == "EXPUNGE":
                self._event(
                    None,
                    "expunge_observed",
                    f"sequence {toks[1]} in current response stream (never a UID)",
                )
                return
            if is_fetch(resp):
                try:
                    parsed = parse_fetch(resp)
                except ParseError:
                    return
                if parsed.uid is not None:
                    self._observe_flags(
                        parsed.uid, parsed, "unsolicited FETCH FLAGS during inventory"
                    )

        spec = f"UID 1:{self.bound - 1}"
        resp = self.session.command("UID", ["SEARCH", spec], handler)
        if (resp.tagged_status() or "").upper() != "OK":
            raise CollectorError(f"UID SEARCH failed: {resp.tagged_text()}")
        if not seen:
            # "No answer" is not "no messages": the inventory is unusable.
            raise CollectorError("server returned no SEARCH response")
        result = {uid for uid in found if 1 <= uid < self.bound}
        self.observed |= result
        self._event(None, f"inventory_{label}", format_uid_set(result))
        return result

    # -- bodies --------------------------------------------------------
    def _receive_phase(self) -> None:
        passes = 0
        while True:
            passes += 1
            work = self._unsettled()
            if not work:
                return
            if passes > 4:
                self._event(
                    None,
                    "passes_exhausted",
                    "unresolved bodies: " + format_uid_set(work),
                )
                return
            for uid in work:
                if self.session.lost is not None:
                    raise self.session.lost
                self._process_uid(uid)
                if self.session.lost is not None:
                    raise self.session.lost
            # Re-check within the fixed range after every pass; an arriving
            # message may be visible below the bound on some servers.
            self.present = self._inventory("mid")

    def _unsettled(self) -> list[int]:
        """UIDs below the bound that still lack a verified body.

        Only UIDs the server currently lists are attempted; a UID that is no
        longer listed is settled by the inventory/reconciliation step, never
        by a missing reply.
        """
        expunged = self.store.expunged_uids(self.generation_id)
        out: list[int] = []
        for uid in sorted(self.present):
            if uid < 1 or uid >= self.bound:
                continue
            row = self.store.message(self.generation_id, uid)
            if row is not None and (
                row["complete"] or row["status"] == "conflict_kept_original"
            ):
                continue
            if row is not None and row["body_digest_pinned"]:
                # Bytes changed under this UID; the round reports it rather
                # than attempting to stitch a body from different responses.
                continue
            if uid in expunged:
                continue
            if self.attempts.get(uid, 0) >= 2:
                continue
            out.append(uid)
        return out

    def _process_uid(self, uid: int) -> None:
        assert self.generation_id is not None
        self.attempts[uid] = self.attempts.get(uid, 0) + 1
        row = self.store.ensure_message(self.generation_id, uid)
        if row["complete"] or row["status"] == "conflict_kept_original":
            return
        data = self._fetch_metadata(uid, row)
        if data is None:
            # No reply is not deletion evidence; final inventory decides.
            self._event(uid, "fetch_no_reply", "UID FETCH (metadata) returned nothing")
            return
        row = self.store.message(self.generation_id, uid) or row
        if row["complete"] or row["status"] == "conflict_kept_original":
            return
        if data.size is None:
            self._event(uid, "no_size", "server did not report RFC822.SIZE")
            return
        if row["expected_size"] is not None and int(row["expected_size"]) != data.size:
            self._event(
                uid,
                "size_changed",
                f"RFC822.SIZE {row['expected_size']} -> {data.size}",
            )
        if row["expected_size"] != data.size:
            self.store.set_expected_size(int(row["id"]), data.size)
            row = self.store.message(self.generation_id, uid) or row
        size = row["expected_size"]
        if size is None:
            self._event(uid, "no_size", "server did not report RFC822.SIZE")
            return
        if size == 0:
            self._complete_empty(uid, row)
            return
        self._download(uid, int(size), row)

    # -- metadata fetch -------------------------------------------------
    def _fetch_metadata(self, uid: int, row) -> FetchData | None:
        return self._uid_fetch(
            uid,
            "(UID FLAGS RFC822.SIZE)",
            want_body=False,
            source="UID FETCH FLAGS (separate metadata pass)",
        )

    def _uid_fetch(
        self,
        uid: int,
        spec: str,
        *,
        want_body: bool,
        source: str,
    ) -> FetchData | None:
        assert self.generation_id is not None
        collected: list[FetchData] = []
        vanished: set[int] = set()
        sequence_expunges: list[str] = []
        ctx: BodyContext | None = None

        def handler(resp: Response) -> None:
            self._note_modseq(resp)
            if resp.is_tagged():
                return
            toks = resp.tokens()
            if len(toks) >= 3 and toks[0] == "*" and toks[2].upper() == "EXPUNGE":
                # Sequence numbers belong to this response stream only.  They
                # are recorded as an observation and never mapped onto a UID,
                # so a later FETCH can never be paired with the wrong message.
                seq_no = toks[1] if toks[1].isdigit() else "?"
                sequence_expunges.append(seq_no)
                self._event(
                    None,
                    "expunge_observed",
                    f"sequence {seq_no} in current response stream (never a UID)",
                )
                return
            if len(toks) >= 2 and toks[1].upper() == "VANISHED":
                vanished.update(_vanished_uids(resp))
                return
            if is_fetch(resp):
                try:
                    parsed = parse_fetch(resp)
                except ParseError as exc:
                    self._event(None, "fetch_parse_error", str(exc)[:300])
                    return
                if parsed.uid is None:
                    self._event(None, "fetch_without_uid", resp.head_text(300))
                    return
                if parsed.uid != uid:
                    # A body literal for another message is never persisted.
                    self._event(parsed.uid, "unsolicited_fetch", "other UID in reply")
                    if ctx is not None:
                        ctx.rejected = True
                        ctx.reject_reason = (
                            f"response named UID {parsed.uid}, requested {uid}"
                        )
                    self._observe_flags(parsed.uid, parsed, "unsolicited FETCH FLAGS")
                    return
                collected.append(parsed)

        expected_origin = self.body_origin or 0
        if want_body:
            assert self.body_origin is not None and self.body_size is not None
            ctx = BodyContext(
                uid=uid,
                origin=expected_origin,
                max_size=self.body_size,
                commit_early=self._commit_early_literal,
            )
            self.session.body_context = ctx
        else:
            ctx = None
            self.session.body_context = None
        self.body_context = ctx
        resp = None
        try:
            resp = self.session.command("UID", ["FETCH", str(uid), spec], handler)
        finally:
            self.session.body_context = None
            self.body_context = None
        if resp is None:
            raise ConnectionLost("UID FETCH was interrupted")
        if (resp.tagged_status() or "").upper() != "OK":
            if ctx is not None:
                for body in ctx.literals:
                    if body.ref.path:
                        Path(body.ref.path).unlink(missing_ok=True)
            raise CollectorError(f"UID FETCH {uid} failed: {resp.tagged_text()}")

        if ctx is not None and want_body:
            self._commit_body_literals(uid, ctx, expected_origin)
        if vanished:
            self._record_vanished(vanished)
        if len(collected) > 1:
            self._event(uid, "multiple_fetches", f"{len(collected)} replies for one UID")
        if not collected:
            return None
        data = collected[-1]
        if data.flags is not None:
            self._observe_flags(uid, data, source)
        return data

    def _observe_flags(self, uid: int, data: FetchData, source: str) -> None:
        assert self.generation_id is not None
        row = self.store.message(self.generation_id, uid)
        if row is None:
            return
        if data.flags is None:
            return
        self.store.observe_flags(
            int(row["id"]), data.flags, data.modseq, source=source, round_id=self.round_id
        )
        self._event(uid, "flags_observed", f"{sorted(data.flags)} source={source}")

    def _record_vanished(self, uids: set[int]) -> None:
        assert self.generation_id is not None
        for uid in sorted(uids):
            if uid < 1:
                continue
            self.store.mark_expunged(self.generation_id, uid, "VANISHED response")
            self.store.add_vanished(self.generation_id, uid, int(self.round_id))
            self.observed.add(uid)
            self._event(uid, "vanished", "explicit VANISHED from server")

    # -- chunk download --------------------------------------------------
    body_origin: int | None = None
    body_size: int | None = None
    body_context: BodyContext | None = None

    def _download(self, uid: int, size: int, row) -> None:
        assert self.generation_id is not None
        message_id = int(row["id"])
        stored_end = self.store.max_part_end(message_id) or 0
        if stored_end > size:
            self._conflict(uid, f"stored parts end at {stored_end}, server size {size}")
            return
        self._event(
            uid,
            "download_start",
            f"size={size} resuming_at={stored_end} chunk={self.config.chunk_size}",
        )
        while stored_end < size:
            chunk = min(self.config.chunk_size, size - stored_end)
            self.body_origin = stored_end
            self.body_size = chunk
            try:
                self._uid_fetch(
                    uid,
                    f"(UID BODY.PEEK[]<{stored_end}.{chunk}>)",
                    want_body=True,
                    source="body fetch",
                )
            finally:
                self.body_origin = None
                self.body_size = None
            current = self.store.message(self.generation_id, uid)
            if current is not None and current["status"] == "conflict_kept_original":
                return
            new_end = self.store.max_part_end(message_id) or 0
            if new_end <= stored_end:
                self._event(uid, "chunk_not_stored", f"offset {stored_end}")
                return
            stored_end = new_end
        self._finish_message(uid, message_id, size)

    def _finish_message(self, uid: int, message_id: int, size: int) -> None:
        assert self.generation_id is not None
        assert self.uidvalidity is not None
        try:
            result = assemble_message(
                self.store, self.layout, self.mailbox, self.uidvalidity, uid, size
            )
        except ConflictError as exc:
            self._conflict(uid, str(exc))
            return
        except AssemblyError as exc:
            self._event(uid, "assembly_error", str(exc)[:500])
            return
        self._event(
            uid,
            "complete",
            f"length={result['length']} sha256={result['sha256']}",
        )

    def _complete_empty(self, uid: int, row) -> None:
        assert self.generation_id is not None
        assert self.uidvalidity is not None
        target = self.layout.message_file(self.mailbox, self.uidvalidity, uid)
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(b"").hexdigest()
        if not target.exists():
            tmp = target.with_name(f".{uid}.eml.tmp-{os.getpid()}")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            with os.fdopen(fd, "wb") as fh:
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        self.store.mark_complete(int(row["id"]), digest, 0, str(target), None)
        self._event(uid, "complete", "length=0 sha256=" + digest)

    def _conflict(self, uid: int, reason: str) -> None:
        assert self.generation_id is not None
        row = self.store.message(self.generation_id, uid)
        if row is None:
            return
        self.store.set_status(int(row["id"]), "conflict_kept_original", reason)
        if not row["complete"]:
            # No verified whole body exists; never assemble one from a mix of
            # old and new server bytes.
            self.store.pin_body(int(row["id"]))
        self._event(uid, "conflict_kept_original", reason[:500])

    # -- metadata refresh ------------------------------------------------
    def _refresh_metadata(self) -> None:
        if self.bound <= 1:
            self._event(None, "metadata_skipped", "empty range")
            return
        vanished: set[int] = set()
        seen: dict[int, FetchData] = {}

        def handler(resp: Response) -> None:
            self._note_modseq(resp)
            if resp.is_tagged():
                return
            toks = resp.tokens()
            if len(toks) >= 2 and toks[1].upper() == "VANISHED":
                vanished.update(_vanished_uids(resp))
                return
            if is_fetch(resp):
                try:
                    parsed = parse_fetch(resp)
                except ParseError as exc:
                    self._event(None, "fetch_parse_error", str(exc)[:300])
                    return
                if parsed.uid is None:
                    self._event(None, "fetch_without_uid", resp.head_text(300))
                    return
                seen[parsed.uid] = parsed

        spec = "(UID FLAGS RFC822.SIZE)"
        modifier = ""
        if self.condstore and self.baseline is not None:
            modifier = f" (CHANGEDSINCE {self.baseline}{' VANISHED' if self.qresync else ''})"
            self._event(None, "metadata_incremental", f"CHANGEDSINCE {self.baseline}")
        else:
            self._event(None, "metadata_full", "complete flag inventory")
        args = ["FETCH", f"1:{self.bound - 1}", spec]
        if modifier:
            args.append(modifier.strip())
        try:
            resp = self.session.command("UID", args, handler)
        except CollectorError:
            raise
        if (resp.tagged_status() or "").upper() != "OK":
            self._event(None, "metadata_failed", resp.tagged_text()[:300])
            return
        if vanished:
            self._record_vanished(vanished)
        assert self.generation_id is not None
        for uid, data in sorted(seen.items()):
            if uid < 1 or uid >= self.bound:
                continue
            row = self.store.ensure_message(self.generation_id, uid)
            if data.flags is not None:
                self.store.observe_flags(
                    int(row["id"]),
                    data.flags,
                    data.modseq,
                    source="inventory flags observation (not body-time flags)",
                    round_id=self.round_id,
                )
            if data.size is not None and row["complete"]:
                if (
                    row["body_length"] is not None
                    and int(row["body_length"]) == data.size
                ):
                    continue
                if int(row["body_length"] or -1) != data.size:
                    self._event(
                        uid,
                        "size_after_complete",
                        f"server size {data.size} != archived {row['body_length']}",
                    )
                    self._conflict(
                        uid,
                        f"server reports size {data.size} but archived body is "
                        f"{row['body_length']} bytes; original kept",
                    )

    # -- reconciliation ---------------------------------------------------
    def _reconcile(self, final_present: set[int]) -> RoundResult:
        assert self.generation_id is not None
        assert self.uidvalidity is not None
        assert self.round_id is not None
        expunged = self.store.expunged_uids(self.generation_id)
        rows = {
            int(row["uid"]): row
            for row in self.store.messages_for_generation(self.generation_id)
            if int(row["uid"]) < self.bound
        }
        complete: list[int] = []
        missing: list[int] = []
        unresolved: list[int] = []
        conflicts: list[int] = []
        expunged_complete: list[int] = []

        candidates = {
            uid
            for uid in (set(rows) | self.observed | final_present)
            if 1 <= uid < self.bound
        }
        for uid in sorted(candidates):
            row = rows.get(uid)
            if row is not None and row["status"] == "conflict_kept_original":
                # The archive keeps the first verified bytes; the change is
                # reported, never silently absorbed.  Progress may only pass a
                # conflict when a verified body for that UID exists.
                verified = bool(row["complete"])
                if verified:
                    complete.append(uid)
                    conflicts.append(uid)
                    self.store.set_inventory(
                        self.round_id, uid, "complete_conflict", "kept_original_bytes"
                    )
                    self._event(
                        uid,
                        "kept_original_after_change",
                        (row["conflict_reason"] or "")[:300],
                    )
                    continue
                conflicts.append(uid)
                self.store.set_inventory(
                    self.round_id, uid, "conflict", "kept_original_bytes"
                )
                continue
            if (
                row is not None
                and row["status"] == "conflict_kept_original"
                and row["complete"]
            ):
                # The change was detected, but a verified body already exists:
                # the original bytes are kept and the UID counts as delivered.
                complete.append(uid)
                conflicts.append(uid)
                self.store.set_inventory(
                    self.round_id, uid, "complete_conflict", "kept_original_bytes"
                )
                self._event(
                    uid,
                    "kept_original_after_change",
                    (row["conflict_reason"] or "")[:300],
                )
                continue
            if (
                row is not None
                and row["status"] == "conflict_kept_original"
                and not row["complete"]
            ):
                # Conflict with no verified body: never claim delivery.
                conflicts.append(uid)
                self.store.set_inventory(
                    self.round_id, uid, "conflict", "kept_original_bytes"
                )
                continue
            if row is not None and row["complete"]:
                complete.append(uid)
                if uid not in final_present:
                    # Archived bytes are kept; the disappearance is recorded
                    # with the same fixed-range evidence used for missing UIDs.
                    reason = expunged.get(uid, "absent_from_complete_final_inventory")
                    if uid not in expunged:
                        self.store.mark_expunged(self.generation_id, uid, reason)
                    expunged_complete.append(uid)
                    self.store.set_inventory(
                        self.round_id, uid, "complete_expunged", "body kept; " + reason
                    )
                    self._event(uid, "complete_then_absent", reason)
                else:
                    self.store.set_inventory(
                        self.round_id, uid, "complete", "body_verified"
                    )
                continue
            if uid in final_present:
                unresolved.append(uid)
                self.store.set_inventory(
                    self.round_id, uid, "unresolved", "present_without_complete_body"
                )
                continue
            reason = expunged.get(uid, "absent_from_complete_final_inventory")
            self.store.mark_expunged(self.generation_id, uid, reason)
            missing.append(uid)
            self.store.set_inventory(
                self.round_id,
                uid,
                "missing",
                "expunge_evidence"
                if uid in expunged
                else "absent_from_complete_final_inventory",
            )
            self._event(uid, "missing", reason)

        for uid in sorted(final_present - set(rows)):
            self.store.ensure_message(self.generation_id, uid)
            self.attempts.setdefault(uid, 0)
            if uid not in unresolved:
                unresolved.append(uid)
            self.store.set_inventory(
                self.round_id, uid, "unresolved", "appeared_during_round_without_body"
            )

        # Re-read: the loop above may have recorded new disappearance evidence.
        expunged = self.store.expunged_uids(self.generation_id)
        # A change to already-verified bytes is reported but does not block:
        # the original body is retained.  Conflicts without a verified body do.
        blocking_conflicts = [uid for uid in conflicts if uid not in complete]
        blocked = sorted(set(unresolved) | set(blocking_conflicts))
        progress = self._frontier(final_present, expunged)
        if blocked:
            progress = min(progress, blocked[0])
            self._event(None, "progress_held", f"first blocked UID {blocked[0]}")
        if progress > 1:
            self.store.advance_progress(self.round_id, progress)
            self._event(None, "progress", f"uid_next_progress={progress}")

        if blocked:
            detail = "unresolved: " + format_uid_set(unresolved)
            if blocking_conflicts:
                detail += " conflicts: " + format_uid_set(blocking_conflicts)
            self.store.set_round_error(self.round_id, detail)
            self._event(None, "round_incomplete", detail)
            status = "incomplete"
        else:
            self.store.finish_round(self.round_id, self.final_highestmodseq)
            self.store.update_generation_seen(
                self.generation_id, self.bound, self.final_highestmodseq
            )
            self._event(
                None,
                "round_complete",
                f"complete={format_uid_set(complete)} "
                f"missing={format_uid_set(missing)}",
            )
            status = "complete"

        self._cleanup_spool()
        return RoundResult(
            mailbox=self.mailbox,
            uidvalidity=self.uidvalidity,
            generation_id=self.generation_id,
            round_id=self.round_id,
            status=status,
            uidnext_at_round=self.bound,
            progress=progress,
            present=sorted(final_present),
            missing=missing,
            complete=complete,
            unresolved=sorted(unresolved),
            conflict=sorted(set(conflicts)),
            expunged_complete=sorted(expunged_complete),
            resumed=self.resumed,
            condstore=self.condstore,
            qresync=self.qresync,
            full_inventory=self.full_inventory,
            baseline=self.baseline,
            highestmodseq=self.final_highestmodseq,
            error=None
            if not blocked
            else (
                "unresolved: " + format_uid_set(unresolved)
                + (
                    " conflicts: " + format_uid_set(blocking_conflicts)
                    if blocking_conflicts
                    else ""
                )
            ),
            events=len(self.store.events(self.round_id)),
        )

    def _frontier(self, present: set[int], expunged: dict[int, str]) -> int:
        """First UID below the bound that is not settled; ``bound`` if none."""
        assert self.generation_id is not None
        rows = {
            int(row["uid"]): row
            for row in self.store.messages_for_generation(self.generation_id)
            if int(row["uid"]) < self.bound
        }
        candidates = {uid for uid in rows if 1 <= uid < self.bound}
        candidates |= {uid for uid in present if 1 <= uid < self.bound}
        candidates |= {uid for uid in self.observed if 1 <= uid < self.bound}
        for uid in sorted(candidates):
            row = rows.get(uid)
            if row is not None and row["complete"]:
                continue
            if row is not None and row["status"] == "conflict_kept_original":
                return uid
            if row is None:
                # Known only from an observation and no longer listed: the
                # reconciliation step records the evidence; it does not block.
                continue
            if uid in expunged:
                continue
            return uid
        return self.bound

    def _cleanup_spool(self) -> None:
        try:
            entries = list(self.layout.spool.iterdir())
        except OSError:
            return
        for path in entries:
            if path.is_file():
                try:
                    path.unlink()
                except OSError:
                    pass


def verify_integrity(store: Store) -> list[str]:
    """Check that no committed progress has skipped a missing body."""
    problems: list[str] = []
    rows = store.conn.execute(
        "SELECT r.*, g.uidvalidity, m.name AS mailbox FROM rounds r "
        "JOIN generations g ON g.id=r.generation_id "
        "JOIN mailboxes m ON m.id=r.mailbox_id WHERE r.status IN ('open','complete')"
    ).fetchall()
    for round_row in rows:
        progress = int(round_row["uid_next_progress"])
        expunged = store.expunged_uids(int(round_row["generation_id"]))
        messages = store.messages_for_generation(int(round_row["generation_id"]))
        for row in messages:
            uid = int(row["uid"])
            if uid >= progress:
                break
            if row["complete"] or row["status"] == "conflict_kept_original":
                continue
            if uid in expunged:
                continue
            problems.append(
                f"round {round_row['id']} ({round_row['mailbox']}/"
                f"{round_row['uidvalidity']}): progress={progress} but UID {uid} "
                "has no verified body and no disappearance evidence"
            )
        for row in messages:
            if not row["complete"]:
                continue
            path = Path(row["body_path"])
            if not path.is_file():
                problems.append(
                    f"round {round_row['id']}: UID {row['uid']} marked complete "
                    f"but {path} is missing"
                )
    return problems
