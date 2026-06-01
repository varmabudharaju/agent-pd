# pd watch — live agent "police scanner"

**Date:** 2026-06-01
**Status:** Design approved
**Builds on:** agent-pd v1 (hook, investigator, detectors, report)

## Goal

A live terminal feed (`pd watch`) that streams agent activity as it happens, with
strong at-a-glance signalling so the user instantly sees which agent is doing what and
which "crimes" (rule offenses) it's committing — without waiting for an after-the-fact
`pd report`.

## Why it works

The patrol hook is registered on `PostToolUse` (fires for *every* tool call) plus
`PermissionDenied`/`SubagentStart`/`SubagentStop`, and appends each event live to
`~/.claude/pd/audit/<session>.jsonl`. So `pd watch` just follows that file and reacts.
Zero new dependencies (ANSI escapes only) → works over SSH / phone.

## UX

```
 agent-pd · watching session 0affa928 · 3 agents active            [Ctrl-C to stop]
────────────────────────────────────────────────────────────────────────────────
┌ ▸ Explore · a93c  started
│   brief: "find all callers of authenticate() and map the call graph"
└─
 12:01:03  Explore·a93c   Grep    "authenticate\("            ✓ on-task
 12:01:06  gp·a55d        Bash    sudo rm -rf /tmp/cache      🚨 CRITICAL  permission_bypass
                                   └ escalation pattern 'sudo ' in command
 12:01:09  Explore·a93c   WebFetch docs.python.org/ast        👁 REVIEW    off_task
                                   └ overlap 0.04 with brief · low-confidence
────────────────────────────────────────────────────────────────────────────────
 RAP SHEET   Explore·a93c: 1 review   ·   gp·a55d: 1🚨   ·   total 2 crimes / 3 acts
```

### Signalling
| Severity | Badge | Style |
|---|---|---|
| critical (permission_bypass) | `🚨 CRITICAL` | red bold |
| high (out_of_scope) | `⚠ HIGH` | yellow |
| low (redundant) | `● LOW` | magenta |
| review (off_task) | `👁 REVIEW` | blue |
| clean | `✓` | dim |

- Each agent gets a **stable color** (hashed from agent_id) + short tag `type·id4`, so
  the user can visually follow one agent's thread.
- **Agent banner** on first sight (or SubagentStart): shows the assigned brief → gives
  context for every following line.
- **Feed line:** `time · agent · TOOL · summary · verdict`. Clean actions dimmed;
  offenses add an indented `└ <why>` reason line.
- **Live rap-sheet footer:** per-agent crime tally, total crimes / total actions.
- **On Ctrl-C:** print a final rap sheet (per agent: actions, crimes by type, worst).

### Flags
- `--session <id>` — pin a session (default: most-recently-active audit file).
- `--crimes-only` — hide clean actions; pure crime feed.
- `--no-color`, `--no-emoji` — plain output for minimal terminals.
- `--audit-dir` / `--projects-dir` — overrides (testing + non-default installs).

## Architecture

Two new modules; reuse existing detectors.

### `agent_pd/render.py` (pure, testable — no I/O)
- `action_summary(tool_name, tool_input) -> str` — concise per-tool description
  (Bash→command, Grep/Glob→pattern, Read/Write/Edit→file_path, WebFetch→url,
  WebSearch→query, else→truncated json).
- `SEVERITY_STYLE` — maps severity → (badge, emoji, ansi-color).
- `Style` — holds `color`/`emoji` booleans; `paint(text, color)` applies ANSI or not.
- `format_banner(agent_type, agent_id, brief, style) -> str`
- `format_feed_line(ts, agent_type, agent_id, tool_name, tool_input, offenses, style) -> list[str]`
  (returns the main line + any `└ why` reason lines; empty if `crimes_only` and clean).
- `format_rap_sheet(tallies, total_acts, style) -> str`
- `agent_tag(agent_type, agent_id) -> str` and `agent_color(agent_id) -> int`.

### `agent_pd/live.py` (state + I/O loop)
- `LiveMonitor` — per-agent state:
  - `records: dict[agent_id -> AgentRecord]` (brief loaded lazily from meta.json via
    `investigator.find_subagents_dir` + `load_meta`),
  - `emitted: dict[agent_id -> set[offense_key]]` (so each offense prints once),
  - `tallies: dict[agent_id -> Counter(severity)]`, `total_acts`.
  - `process(event, rules) -> ProcessResult` with fields: `banner` (str|None, set when
    the agent is first seen), `feed_lines` (list[str]), `new_offenses` (list[Offense]).
    Builds/extends the agent's AgentRecord with one Action from the event, runs
    `run_detectors` over the record, diffs vs `emitted` to find *new* offenses, updates
    tallies, and asks `render` to format. Offense key = `(offense, evidence)`.
- `tail_events(audit_dir, session_id=None, poll_interval=0.5, _max_idle=None) -> iterator`
  — resolves the session file (most-recent if None), follows it appending-style
  (tracks byte offset; tolerant of the file not existing yet and of partial/blank
  lines), yields parsed event dicts. `_max_idle` lets tests terminate the loop.
- `watch(session=None, crimes_only=False, style=..., audit_dir=..., projects_dir=...,
  out=print) -> int` — orchestration: header, loop over `tail_events`, feed
  `process`, print results; on `KeyboardInterrupt` print final rap sheet. `out` is
  injectable for tests.

### `agent_pd/cli.py`
- Add `watch` subcommand wiring the flags above to `live.watch`.

## Live-detection notes
- Detectors run over the **accumulating** per-agent `AgentRecord`; only *newly appeared*
  offenses (by key) are emitted. This reuses all four detectors unchanged. `redundant`
  naturally fires when the 2nd duplicate arrives; `off_task`/`permission_bypass` fire on
  their action's turn.
- Brief is read lazily from `meta.json`; if absent (e.g. main-thread events with empty
  agent_id), `off_task` simply yields nothing (empty brief → skip), which is correct.
- The audit log now contains *all* PostToolUse events (allows), so the live action
  feed is complete; the after-the-fact `pd report` path is unaffected (it still only
  merges `deny` events from the audit log, since allows are already in transcripts).

## Out of scope
- TUI / web dashboard (separate future feature; all read the same audit log).
- Persisting the live feed to a file (the audit log already is the persistent record).
- LLM-judge offenses (v2, shared with the report path).

## Testing
- `tests/test_render.py`: action_summary per tool; badge/severity mapping; banner shows
  brief; feed line shows verdict + reason; `crimes_only` suppresses clean lines;
  `--no-color`/`--no-emoji` produce plain text; rap sheet aggregates.
- `tests/test_live.py`: `LiveMonitor.process` emits a banner once per agent; emits each
  offense once (no repeats on subsequent actions); tallies aggregate; `tail_events`
  yields appended lines from a temp file and tolerates blank/partial lines.
