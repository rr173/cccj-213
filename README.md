# imaparchive

A read-only IMAP collector that archives the **original RFC 3501 message bytes**
of one configured mailbox into an offline, inspectable data store.

It is designed around the fact that a live mailbox is not a stable snapshot:

* new mail arrives during a round,
* old mail is expunged while other mail is being downloaded,
* flags change,
* the TCP connection can die in the middle of a literal,
* `UIDVALIDITY` can change and UIDs can be reused by a different message.

The collector never infers identity from sequence numbers, never merges
messages by `Message-ID` or body bytes, never sends mail, never writes flags and
never deletes anything on the server.

## Identity model

A logical message is identified by exactly:

```
(configured mailbox name, UIDVALIDITY, UID)
```

* `Message-ID` and body digests are catalogue attributes only.
* Within one generation `(mailbox, UIDVALIDITY)`, the bytes archived for a UID
  are **never silently replaced**. If the server later returns different bytes
  for the same UID, the original verified body is kept and the UID is recorded
  as `conflict_kept_original`.
* A change of `UIDVALIDITY` opens a **new generation directory**. The previous
  generation and its archived mail remain readable. No UID range, MODSEQ
  baseline or open round is carried into the new generation; an open round of
  the old generation is closed as `stale`.
* Folder renames and cross-mailbox identity inference are out of scope.

On disk:

```
<data>/
  catalogue.sqlite3
  spool/                                    # transient literal spool (never published)
  generations/<mailbox>/<uidvalidity>/
    messages/<uid>.eml                      # only complete, verified bodies
    parts/<uid>.<origin>.part               # verified fixed-size chunks
```

## Rounds

Every invocation of `collect` runs (or resumes) exactly one **round**:

1. `CAPABILITY`; `ENABLE QRESYNC` when offered.
2. `EXAMINE` the mailbox (read-only) and record `UIDVALIDITY`, `UIDNEXT`,
   `HIGHESTMODSEQ`, and whether the server said `NOMODSEQ`.
3. Fix the reception bound to the **`UIDNEXT` observed at selection**. Only
   UIDs strictly below that bound are received; a larger UID that arrives later
   waits for the next round and is never reported as missing.
4. Complete `UID SEARCH` inventory of the fixed range.
5. Fetch metadata (`UID FLAGS RFC822.SIZE`) and bodies
   (`BODY.PEEK[]<origin.count>`) in fixed-size chunks.
6. A complete inventory is taken again after reception.
7. Only when every unresolved body, catalogue update and increment event is
   settled does the round commit `uid_next_progress` and (if nothing is
   unresolved) become `complete`.

Untagged `EXPUNGE` sequence numbers are recorded as observations **only**. They
are meaningful within the current response stream and are never mapped onto a
UID, so a later `FETCH` cannot be paired with the wrong message.

### Deletion evidence

A UID is only treated as gone when there is explicit evidence:

* a `VANISHED` response (with QRESYNC), or
* absence from a **complete** inventory of the fixed range. Because UIDs below
  this round's `UIDNEXT` cannot be reassigned, absence there is evidence.

A `FETCH` that returns no data is *not* evidence; such a UID stays `unresolved`
and blocks progress.

### Incremental vs. full

When `CONDSTORE`/`QRESYNC` are available **and** a provably valid baseline
exists (`HIGHESTMODSEQ` from the last complete round, still ≤ the current
`HIGHESTMODSEQ`), flags/VANISHED are refreshed with
`CHANGEDSINCE <baseline> (VANISHED)`. Otherwise — capability missing,
`NOMODSEQ`, no previous round, or no trustworthy baseline — the round does a
complete UID inventory. Both modes end at the same confirmed catalogue.

## Connection loss and literals

* Literals are consumed by their advertised octet count. CRLF, tag-looking text,
  NUL bytes and `)` inside a body never leak into protocol parsing; unknown
  responses still have their literals consumed exactly.
* A body literal is spooled to a private temp file; it becomes a `parts/` file
  only after the enclosing `FETCH` has been parsed and the response is proven
  to name the requested UID and `BODY[]<origin>`.
* A connection that dies mid-literal keeps only the chunks that were already
  fully read **and** attributed; the next round resumes at the highest verified
  `origin` for the same generation and UID. Chunks from another message are
  never concatenated.
* A partially received body is never published as `<uid>.eml` and never marks
  the UID complete.

## Catalogue

SQLite (`catalogue.sqlite3`) holds generations, rounds, per-UID parts with
origin/length/SHA-256, flag observations (with source and timestamp — never
described as flags at body-fetch time), the ordered per-round event log, the
final inventory per round, and expunge/VANISHED evidence.

## Usage

Credentials come from the environment and are never written to disk:

| variable | meaning |
| --- | --- |
| `IMAP_HOST` | server host (required) |
| `IMAP_PORT` | port (default 993 for ssl, 143 otherwise) |
| `IMAP_USER` | account (required) |
| `IMAP_PASSWORD` | password (required) |
| `IMAP_MAILBOX` | mailbox name, default `INBOX` |
| `IMAP_TLS` | `ssl` (default), `starttls`, `none` |
| `IMAP_TLS_VERIFY` | `1`/`0` |
| `IMAPARCHIVE_DATA` | archive root, default `./archive` |
| `IMAPARCHIVE_CHUNK_SIZE` | partial-fetch block size, default 65536 |
| `IMAPARCHIVE_TIMEOUT` | socket timeout seconds, default 60 |

```bash
python -m imaparchive collect     # run one round (resumes an open round)
python -m imaparchive resume      # same, explicit
python -m imaparchive check       # generations, rounds, integrity
python -m imaparchive check --uidvalidity 1000 --uid 9
python -m imaparchive export --out ./export   # offline, no network
python -m imaparchive verify      # offline invariant check
```

Exit codes: `0` delivered, `2` round incomplete (queryable/resumable),
`64` configuration, `75` connection lost, `76` IMAP error, `77` auth failure.

`export` writes `<out>/<mailbox>/<uidvalidity>/messages/<uid>.eml` plus
`manifest.jsonl`; it re-verifies every body digest and never contacts a server.

## Tests

The acceptance suite starts a real, scriptable IMAP server on a loopback TCP
port and drives the collector over the network:

```bash
python -m pytest tests -q
```

Covered: EXPUNGE during a download plus a mid-literal disconnect and a byte-exact
resume of the same UID; a UID arriving after the round's `UIDNEXT` (deferred,
not missing); `UIDVALIDITY` change with UID reuse and duplicated `Message-ID`;
incremental vs. full inventory equivalence; `VANISHED`, no-QRESYNC EXPUNGE,
`NOMODSEQ` and no-CONDSTORE downgrades; empty mailbox; message vanishing before
download; auth failure; crash before progress commit; changed bytes under the
same UID; literals containing protocol look-alikes. `tests/test_large.py`
generates multi-megabyte bodies at runtime and asserts bounded memory, reopen
without re-fetch, and offline export — no large mail is committed. The same
trial can be run standalone (it prints peak memory and byte-comparison results):

```bash
python tools/large_trial.py --count 3 --mib 4
```

The password used by the test server exists only in test memory; the server
redacts `LOGIN` in its own log, and a test asserts it never reaches the archive.
