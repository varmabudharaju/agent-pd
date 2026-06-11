# Session identity in pd output

**Date:** 2026-06-09
**Status:** approved (varma, in-session)

## Problem

`pd watch` and `pd list` identify sessions only by UUID. With several Claude Code
sessions on one machine, the user cannot tell which session a feed belongs to —
e.g. `pd watch` attached to `8144b9f4-…` and the user had "no idea what session
this is". Every audit event already records `cwd` and `transcript_path`, but pd
never surfaces them.

## Decision

Derive session identity **at read time** from data already on disk. No change to
the audit log format, the hook, or the integrity chain — so it works
retroactively for every existing session.

Rejected alternatives:

- *SessionStart header event in the log* — doesn't cover existing sessions,
  touches the hash-chain format, copies prompt text into audit logs.
- *Sidecar meta file per session* — future sessions only, more files to manage.

## Design

### `store.session_identity(session_id, audit_dir)`

Returns `{"project": str, "title": str, "last_active": float|None}`.

- **project** — `cwd` of the first event that has one. Reads the plain `.jsonl`
  incrementally (first lines only, never the whole multi-MB file); falls back to
  the `.jsonl.gz` for compacted sessions.
- **title** — first real user prompt, read from the transcript at the event's
  `transcript_path`: first `type == "user"` line whose text is not harness
  output (`<local-command…`, `<command-…`, `<task-notification…`,
  `<system-reminder…`, `Caveat:` prefixes are skipped, as are meta/tool-result
  entries). Collapsed to one line, truncated to 60 chars with `…`.
- **last_active** — mtime of the session's audit file.
- Every field degrades to `""`/`None` if its source is missing (no transcript,
  empty log, etc.). Never raises.

### Surfacing

- **`pd watch` header** (single session — the main fix):

      agent-pd · watching session 8144b9f4-… · ~/mongosemantic · “test this whole repo and features…” · new activity only · <audit-dir>

  Project shown home-relative. Omitted segments collapse cleanly when unknown.

- **`pd watch --all`**: when a session id appears in the merged feed for the
  first time, print one session-intro line before its banner/feed lines:

      § 8144b9f4 · ~/mongosemantic · “test this whole repo and features…”

- **`pd list`**: one row per session, sorted by last activity (newest last),
  showing session id, project, last-active time, and title:

      8144b9f4-7840-…  ~/mongosemantic   Jun 09 21:19  “test this whole repo and features…”

## Testing

- Unit: `session_identity` — cwd from first event; gz fallback; title extraction
  skipping harness noise; missing transcript / missing session → empty fields.
- `watch` header contains project + title (existing `out=`/`_events=` injection).
- `--all` prints the session-intro line once per session.
- `pd list` row format and ordering.
- Manual: run `pd list` and `pd watch` against the real `~/.claude/pd/audit`.
