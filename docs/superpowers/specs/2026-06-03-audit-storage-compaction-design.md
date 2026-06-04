# Audit storage compaction — design

**Date:** 2026-06-03 · **Status:** approved (brainstorming) · **Repo:** `agent-pd`

## Problem

The patrol hook records one normalized JSON line per tool call to
`~/.claude/pd/audit/<session_id>.jsonl` — an append-only file per session. This is a fine
*capture* format but a poor *storage* format:

- **Unbounded growth, no rotation/pruning.** Every session ever is kept, flat, forever.
- **Fat `tool_input` payloads dominate size.** `tool_input` is stored verbatim; a single
  `Write` event was observed at **35 KB** (the full file body). Observed today: 4 sessions,
  1.4 MB, 1,573 events; avg line 839 B, max 35 KB. Line *count* is not the driver — bulky
  string fields are.
- **Reports are ephemeral.** `pd report` recomputes from the audit and prints to stdout;
  nothing about the analysis is persisted. (Out of scope here — see Non-goals.)

We want audit storage that is **scalable** (compression + bulk externalization + retention)
and **provably correct** (deterministic, idempotent, lossless of every fact the detectors or a
"what did the agent do" autopsy actually use). Bulk content must remain *recoverable later*
until explicitly pruned — not silently dropped.

## Approach (chosen)

**Offline `pd compact` + content-addressed, compressed blob store.** The hook stays
**completely untouched** — it remains the dumb, crash-safe, always-exit-0 recorder writing full
JSONL. A separate, deterministic, idempotent `pd compact` pass transforms *old* sessions into a
compact storage form: bulky string fields are externalized into a gzip'd, content-addressed
blob store, the audit line keeps a small reference (`hash + bytes + preview`), and the rewritten
log is gzipped.

Rejected alternatives:
- **Shrink at write-time (in the hook).** Puts blob I/O on the must-never-fail path and
  complicates the one component deliberately kept bulletproof. Rejected.
- **Lossless-only (gzip + rotate, no blob store).** Simplest, but the 35 KB-per-Write driver
  survives inside the gzip and we lose dedup + independent blob-retention dials. Fallback only.

## On-disk formats

Three formats under `~/.claude/pd/`:

```
audit/<sid>.jsonl       ← capture format (hook writes this; UNCHANGED)
audit/<sid>.jsonl.gz    ← storage format (pd compact produces this)
blobs/<ab>/<sha256>.gz  ← content-addressed bulk store (gzip'd, sharded by 2-char sha prefix)
```

A compacted event replaces a bulky string field inline with a reference; every other field
stays byte-for-byte verbatim:

```jsonc
// before:
"tool_input": {"file_path": "x.py", "content": "<35 KB string>"}
// after:
"tool_input": {"file_path": "x.py",
  "content": {"_pd_blob": "<sha256-hex>", "bytes": 35093, "preview": "<first 500 chars>"}}
```

- `_pd_blob` is a **reserved key** chosen so it cannot collide with a real tool-input field.
- The blob file content is the **gzip of the original UTF-8 string bytes**. Content-addressed by
  sha256 of those raw bytes → identical content across sessions is stored exactly once (dedup).
- `bytes` is the original (uncompressed) length; `preview` is the first 500 characters of the
  original string. Both keep an autopsy readable without rehydration.

### Why detection fidelity is preserved exactly

The detectors read only path/tool/agent/decision/reason fields and small inputs — never the
giant `content`/`new_string` body. Those all remain inline. Therefore a report produced over a
compacted session is **identical** to one produced over the raw session. This is asserted by a
test (see Testing).

## Module: `agent_pd/store.py`

The single place that knows the on-disk layout. After this change, nothing else parses audit
paths or reads raw audit files directly.

Surface (pure functions where marked; no network anywhere):

- `shrink_value(obj, threshold) -> (new_obj, blobs)` — **pure.** Recursively walk `obj`
  (dict/list/str/scalar); replace any `str` whose UTF-8 length `> threshold` with a blob-ref
  dict. Returns the transformed object and a list of `(sha256, raw_bytes)` to persist. A dict
  already containing `_pd_blob` is treated as an ordinary dict (its values are small) → no
  re-shrink. This is what makes compaction idempotent.
- `blob_path(sha, blob_dir) -> Path` — **pure.** `blob_dir/<sha[:2]>/<sha>.gz`.
- `put_blob(raw_bytes, blob_dir) -> sha` — gzip + write at `blob_path`. No-op if the file
  already exists (dedup); on an existing blob, refresh its mtime so actively-referenced content
  survives age-based pruning.
- `get_blob(sha, blob_dir) -> bytes` — read + gunzip (rehydrate for deep autopsy).
- `iter_events(session_id, audit_dir) -> Iterator[dict]` — transparently yield parsed events
  from `<sid>.jsonl.gz` if present, else `<sid>.jsonl`. **If both exist** (a compaction/append
  race), yield the `.gz` events first, then any lines from the plain `.jsonl`. Tolerant of
  blank/partial lines (skips them), matching the existing readers.
- `latest_session(audit_dir) -> str | None` — most-recent session by mtime, considering **both**
  `.jsonl` and `.jsonl.gz`.
- `list_sessions(audit_dir) -> list[str]` — distinct session ids from both extensions.
- `compact_session(session_id, audit_dir, blob_dir, threshold) -> CompactStats` — see below.
- `prune_blobs(blob_dir, older_than_days=None, max_bytes=None) -> PruneStats` — see Retention.

### `compact_session` algorithm

Deterministic and idempotent:

1. Read all events via `iter_events` (works whether the session is raw, already compacted, or
   mid-race).
2. For each event, `new_input, blobs = shrink_value(event["tool_input"], threshold)`; set
   `event["tool_input"] = new_input`; accumulate `blobs`.
3. `put_blob` each blob (dedup'd).
4. Serialize rewritten events to a temp file in `audit_dir`, gzip it, **atomic-rename** to
   `<sid>.jsonl.gz`, then `unlink` the original `<sid>.jsonl` if it existed.
5. Idempotent by construction: a second run finds only `_pd_blob` dicts (no over-threshold
   strings) and reproduces identical output.

**Never touch the active session.** `pd compact` with no `--session` compacts every session
*except the most-recently-modified one* (the likely-live log the hook is still appending to).
`--session <id>` forces one; `--all` includes even the latest. Combined with the hook being
untouched, this means compaction never runs underneath an in-progress write. The
`iter_events` both-exist merge is a belt-and-suspenders backstop, not the primary guarantee.

## Integration (detectors / LiveMonitor unchanged)

Switch the four read/resolve sites to `store`:

- `investigator.gather()` — replace the `read_text().splitlines()` loop with
  `store.iter_events(session_id, audit_dir)`.
- `investigator._latest_session` — delegate to `store.latest_session` (keep the existing
  signature/callers).
- `cli._cmd_list` — use `store.list_sessions` for the audit side (still also unions the
  `projects/*/*/subagents` session ids as today).
- `live.py` — tailing (`tail_events` / `tail_all_events`) keeps reading plain `.jsonl`, since it
  only ever follows the active (never-compacted) session. Its "most recent" resolver
  (`_resolve_session_file`) uses `store.latest_session` so `pd watch --session <old>` on a
  compacted session still resolves to the `.gz` and replays it.

Detectors, `LiveMonitor.process`, `models`, `report`, `render` need **no changes**.

## Retention

`prune_blobs(blob_dir, older_than_days=None, max_bytes=None)`:

- Delete blobs whose mtime is older than `older_than_days` (if set).
- If `max_bytes` is set, after the age pass, delete oldest-mtime blobs until total blob bytes
  `<= max_bytes`.
- Pruning a blob loses only deep-content **recovery** — `bytes` + `preview` stay inline and
  **detection is unaffected**. This is the intended recent-recoverable / ancient-summary
  tiering.

**Whole-session pruning is out of scope** (the user wants bookkeeping kept). Documented as a
future dial.

## CLI surface

New `pd compact` subcommand:

```
pd compact [--session <id>] [--all] [--threshold <bytes>]
           [--prune-blobs-older-than <days>] [--max-blob-bytes <n>]
           [--dry-run] [--audit-dir ...] [--blob-dir ...]
```

- Default (no `--session`, no `--all`): compact all sessions except the most-recently-modified.
- `--dry-run`: report what would be compacted/pruned and the projected size delta; write nothing.
- Prints a short summary: sessions compacted, events rewritten, blobs written/dedup'd,
  bytes before→after, blobs pruned.

Blob rehydration for deep autopsy: `pd show --blob <sha>` prints the full original content to
stdout (a thin wrapper over `store.get_blob`). Included — it is the only way to recover bulk
content, and `get_blob` exists regardless. The `_pd_blob` sha printed in any report/JSON is the
handle you pass to it.

## Config

Extend `config.DEFAULTS` / `Rules` with a `storage` section (deep-merged like the rest):

```yaml
storage:
  blob_threshold_bytes: 2048   # strings longer than this are externalized
  preview_chars: 500           # chars of original kept inline for readability
  blob_retention_days: null    # null = keep forever (default)
  max_blob_bytes: null         # null = no size cap (default)
```

CLI flags override config; config overrides defaults. Defaults are conservative: 2048 B
threshold leaves normal events (avg 839 B) fully inline and only externalizes the fat ones;
retention defaults to keep-everything so behavior is opt-in.

## Testing (all deterministic, no network)

In `tests/` alongside the existing suite:

- `shrink_value`: small strings unchanged; over-threshold string → correct `_pd_blob`/`bytes`/
  `preview`; nested dict/list recursion; idempotent on an already-shrunk object; multibyte/UTF-8
  length measured in bytes.
- `put_blob`/`get_blob`: round-trip; dedup (same content → one file, second `put` is a no-op);
  sharded path layout; mtime refresh on re-put.
- `compact_session`: **lossless** — rehydrating every `_pd_blob` reconstructs the original event
  exactly; **idempotent** — running twice yields byte-identical `.gz`; atomic (original removed
  only after `.gz` written); active-session-skip behavior.
- `iter_events`: reads `.jsonl`; reads `.jsonl.gz`; both-present merge order (gz then plain);
  tolerates blank/partial lines.
- `latest_session` / `list_sessions`: consider both extensions; correct most-recent selection.
- **Equivalence (the key correctness test):** build a session with a 35 KB Write + a denial +
  out-of-scope reads; assert `gather()` + `run_detectors` over the raw session and over the
  compacted session produce **identical offenses**.
- `prune_blobs`: age-based deletion; `max_bytes` cap deletes oldest first; never deletes a blob
  whose mtime was just refreshed.

## Non-goals (this spec)

- Persisting rendered reports / offense snapshots / judge verdicts (a separate "frozen report"
  spec).
- Cross-session search / index / manifest.
- Capturing tool *outcomes* (only inputs are logged today — a hook-side change, deliberately not
  touched here).
- Whole-session pruning.

## Working conventions

Per `SESSION-HANDOFF.md`: TDD throughout; pure, unit-tested helpers; strip AI-attribution
trailers before push; land via branch → PR → **rebase-merge** (never squash).
