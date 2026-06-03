# agent-pd — richer, clearer `pd report`

**Date:** 2026-06-02
**Status:** Design approved (brainstorm), pre-spec-review
**Scope:** Presentation-only enhancement to `pd report` — named main agent, per-agent
digest, and drill-down (`--verbose`, `--agent <id>`, files-touched). No detector *logic*
changes; only where evidence is truncated moves from detectors to the render layer.

## Problem

`pd report` is terse: the main agent shows as `agent: ? (…)` with an empty id, every agent
is just a table of offenses with no "what did it do" context, and evidence is hard-truncated
at ~120 chars with no way to see the full command. The user wants (1) a meaningful main-agent
name, (2) useful per-agent info, (3) a way to see more detail on demand.

## Design

### 1. Per-agent name + digest (default) — new `agent_pd/summary.py`

Pure helpers (no I/O), unit-testable:

- `agent_label(record, session_id=None) -> str`:
  - main agent (`agent_id == ""`): `main · <project> (session <sid7>)` where `<project>` is
    `os.path.basename(record.cwd.rstrip("/"))` (omit the ` · <project>` clause if cwd empty),
    and `(session <sid7>)` is the first 7 chars of `session_id` (omitted if None).
  - subagent: `<agent_type or '?'> (<agent_id[:8]>…)`.
- `agent_digest(record, agent_offenses) -> dict` with:
  - `acts`: `len(record.actions)`
  - `first`/`last`: `HH:MM` of the min/max non-null `action.ts` (None if no timestamps)
  - `tools`: `Counter(a.tool_name for a in record.actions if a.tool_name)`
  - `files`: ordered-unique list of file paths (`file_path`/`notebook_path`) touched
  - `crimes`: `Counter(o.severity for o in agent_offenses)`
- `format_digest_line(digest, style_emoji=True) -> str`: a compact one-liner, e.g.
  `53 acts · 11:49–17:30 · Bash×24 Edit×12 Read×9 · 1🚨 6⚠ 2● 1ℹ` (top-3 tools; severity
  emojis from `render.SEVERITY_STYLE`; `clean` when no crimes; drop the time clause if no ts).

`pd report` renders this italicized under each `### <label>` header — **for every agent,
including clean ones** (a no-crime agent shows its activity instead of just `_no offenses_`).

### 2. `--verbose` / `-v` — full evidence (truncation moves to render)

Today three detectors pre-truncate their evidence (`permission_bypass._summ` at 120,
`redundant` at 120, `off_task` term/brief at 50). Change them to emit **full** evidence;
`render_markdown` truncates each evidence cell to ~120 chars (with `…`) **by default**, and
not at all under `--verbose`. Consequences:
- `permission_bypass`: `_summ(tool_input)` returns the full `json.dumps(tool_input, sort_keys=True)` (drop the limit).
- `redundant`: evidence uses the full key payload (drop `[:120]`).
- `off_task`: evidence uses the full query and full brief (drop the `[:49]+"…"`); `subject` already full.
- `render_json` now always carries full evidence (a bonus).
- `pd watch` is unaffected — `render.format_feed_line` already truncates the reason for display independently.

### 3. `--agent <id>` — focus one agent

`pd report --agent a573f36b` (prefix match against `agent_id`; the literal `main` matches the
empty-id agent) prints only that agent: its label + digest, its offenses (full evidence,
regardless of `--verbose`), **and** a chronological action list — one line per action:
`HH:MM:SS  <Tool>  <summary>` using `render.action_summary` + `render._fmt_ts`. If no agent
matches, print `no agent matching '<id>' in session <sid>`.

### 4. Files-touched (under `--verbose`)

In verbose mode each agent's digest gains a second line: `files: <p1>, <p2>, …` listing
`digest["files"]` (deduped, in first-seen order). Omitted when empty.

### CLI wiring (`agent_pd/cli.py`)

- `report` subparser gains `-v/--verbose` (store_true) and `--agent` (default None).
- `_cmd_report` resolves the session id once so the label can show it:
  `sid = args.session or _latest_session(Path(args.projects_dir), Path(args.audit_dir))`
  (import `_latest_session` from `.investigator`), passes `session_id=sid` to `gather` and to
  `render_markdown(records, offenses, session_id=sid, verbose=args.verbose, only_agent=args.agent)`.
- `render_json` unchanged signature; `--agent`/`--verbose` affect markdown only (json already full).

## Components & boundaries

| Unit | Purpose | Depends on |
|---|---|---|
| `summary.agent_label` | human name for an agent | stdlib |
| `summary.agent_digest` | per-agent activity stats | `collections.Counter` |
| `summary.format_digest_line` | compact one-liner | `render.SEVERITY_STYLE` |
| `report.render_markdown` | layout: header+digest+table(+focus) | `summary`, `render` |
| `cli._cmd_report` | resolve sid, thread flags | `investigator._latest_session` |
| detectors (3) | emit full evidence | — |

## Testing strategy

TDD; pure units tested directly; no network.

- **summary:** `agent_label` for main (with/without cwd, with/without sid) and subagent;
  `agent_digest` acts/first/last/tools/files/crimes from a crafted record+offenses;
  `format_digest_line` shows tools, crime badges, and `clean` when no crimes.
- **report:** main agent header shows `main · <project> (session …)`; digest line present for
  clean and dirty agents; default truncates a >120-char evidence to `…`, `--verbose` shows it
  full; `--agent` focus prints only the matched agent + its chronological actions; unknown
  `--agent` prints the not-found line; `--verbose` adds the `files:` line.
- **detectors:** existing tests updated where they asserted truncated evidence (assert the
  full evidence substring is present and that the `…` is gone); add one test per detector that
  a long input now appears in full in the offense evidence.
- **cli:** `_cmd_report` passes the resolved sid and flags through (smoke via argv parse).
- **regression:** full suite green; real-session smoke `pd report` and `pd report --agent main -v`.

## Out of scope

`pd watch` formatting, JSON schema changes beyond fuller evidence, a standalone `pd summary`
command (this folds the digest into `report` instead). Deferred `KNOWN-GAPS.md` items unchanged.
