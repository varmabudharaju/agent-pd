# agent-pd — a police department for Claude Code subagents

**Date:** 2026-06-01
**Status:** Design approved, pre-implementation
**Scope:** v1

## Problem

When running multiple Claude Code subagents (via the Agent / Workflow tools), some
agents do things that don't lead to the solution: unnecessary or unrelated searches,
actions outside their assigned task, and attempts to bypass permissions. There is no
clear, after-the-fact way to find *which* agent misbehaved, *how*, and with what
evidence.

Claude Code's native observability is strong for interactive debugging (agent view,
transcripts, hooks) but weak for automated compliance auditing of agent behavior. No
off-the-shelf tool reads Claude Code subagent transcripts natively or checks an action
against *that specific subagent's assigned task and tool allowlist*.

## Concept

A two-part system, catch-and-report only (never blocks an agent):

- **The patrol** — a logging-only hook that records the ground-truth event stream live
  as agents run.
- **The investigator** — a CLI (`pd`) that reads the patrol logs plus transcripts after
  a run and produces a **police report** of offenses, each with quoted evidence.

We deliberately do **not** rebuild a general guardrail engine. Invariant Labs Guardrails
(open source, Apache-2.0) already does declarative rule-matching over tool-call sequences.
The defensible, unfilled piece is the thin Claude-Code-native layer:

- parse Claude Code subagent `.jsonl` transcripts,
- check each action against the subagent's declared `tools:` allowlist (deterministic),
- correlate each action against the subagent's assigned task brief.

## Why a hook is required (key constraint)

**Denied / blocked tool calls do NOT appear in transcripts** — Claude Code kills them
before execution. Therefore a pure forensic "read the `.jsonl`" approach physically
cannot see permission-bypass *attempts*. Those are only observable via a hook
(`PermissionDenied` / `PreToolUse`).

A hook that only *logs* (exits 0, returns no decision) is fully compatible with the
"catch + report, no intervention" requirement. So the patrol hook is a pure recorder.

## Architecture

```
   agents run
       │
       ├──(live)──▶  patrol_hook.py  ──▶  ~/.claude/pd/audit/<session-id>.jsonl
       │             (PostToolUse, PermissionDenied,            (ground-truth events,
       │              SubagentStart/Stop)                        incl. denied calls)
       │
       └──(on disk)─▶ ~/.claude/projects/<enc-path>/agent-*.jsonl
                       (transcripts: full tool inputs/results, assigned brief)

   pd report  ──reads──▶ audit log + transcripts + agent defs (tools: allowlist)
              ──correlate by agent_id──▶ detectors ──▶ report (JSON + markdown)
```

## Components

### (a) Patrol hook — `patrol_hook.py`

- Registered in `~/.claude/settings.json` on: `PostToolUse`, `PermissionDenied`,
  `SubagentStart`, `SubagentStop`.
- Reads the hook JSON from stdin. Relevant fields: `agent_id`, `agent_type`,
  `tool_name`, `tool_input`, and (for denials) the permission decision/reason,
  plus `session_id`, `cwd`, timestamp.
- Appends **one structured line** per event to `~/.claude/pd/audit/<session-id>.jsonl`.
- **Always exits 0. Emits no permission decision. Pure recorder — never blocks.**
- Must be fast and crash-safe: any internal error is swallowed and the hook still
  exits 0, so the agent run is never affected.

Audit line schema (one JSON object per line):

```json
{
  "ts": "2026-06-01T12:00:00Z",
  "event": "PostToolUse" | "PermissionDenied" | "SubagentStart" | "SubagentStop",
  "session_id": "...",
  "agent_id": "...",
  "agent_type": "Explore" | "general-purpose" | "...",
  "tool_name": "Bash" | "Grep" | "...",
  "tool_input": { "...": "..." },
  "decision": "allow" | "deny" | null,
  "reason": "string | null",
  "cwd": "..."
}
```

### (b) Investigator — `pd` CLI

- `pd report [--session <id>] [--format json|md|both] [--rules <path>]`
  - Default session: the most recent session in `~/.claude/pd/audit/`.
- Gathers and correlates **by `agent_id`**:
  - the **audit log** (live events, including denials),
  - the subagent **transcripts** (`agent-*.jsonl`) for full tool inputs/results,
  - each agent's **assigned task** (first user message in its transcript) and its
    **tool allowlist** (`tools:` frontmatter when the agent is a custom agent
    definition under `.claude/agents/`; otherwise from rules-config defaults).
- `pd list` — list sessions available in the audit dir with summary counts.

### (c) Detectors (v1 — deterministic)

| Offense | Detector | Method | Confidence |
|---|---|---|---|
| Permission bypass | denial events + escalation patterns (`dangerouslyDisableSandbox`, `sudo`, etc.) | deterministic | high |
| Out-of-scope tool/file | tool ∉ allowlist; file path ∉ scope dirs | deterministic | high |
| Wasteful / redundant | exact-duplicate searches & re-reads of the same target | deterministic | high |
| Off-task / unrelated | token-overlap of search query vs. assigned brief below threshold | heuristic | **low — "for review"** |

**Off-task caveat:** robust off-task judgment requires an LLM judge, which is out of v1
scope. The v1 off-task detector is a heuristic *flag* only, explicitly labeled
low-confidence "for review", never reported as a hard verdict. The real judge lands in v2.

### (d) Rules config — `pd-rules.yaml`

Rules live in config, not code. Fields:

```yaml
scope_dirs: ["src/", "tests/"]        # allowed file roots; outside = out-of-scope
escalation_patterns:                   # substrings/regex marking a bypass attempt
  - "dangerouslyDisableSandbox"
  - "sudo "
  - "chmod 777"
severity:                              # per-offense severity label
  permission_bypass: critical
  out_of_scope: high
  redundant: low
  off_task: review
detectors:                             # toggle individual detectors
  permission_bypass: true
  out_of_scope: true
  redundant: true
  off_task: true
off_task_overlap_threshold: 0.15       # token-overlap floor before flagging
```

### (e) Report output

- **JSON**: machine-readable, full evidence.
- **Markdown**: human-readable table keyed **agent → offense → severity → evidence**,
  where evidence is the exact quoted tool call or audit line.

Example markdown shape:

```
## Police report — session abc123  (4 agents, 3 offenses)

### agent: Explore (a93cc…)  — assigned: "find all callers of foo()"
| severity | offense          | evidence                                            |
|----------|------------------|-----------------------------------------------------|
| critical | permission_bypass| Bash: `sudo rm -rf /tmp/x`  (denied 12:01:33)        |
| review   | off_task         | Grep "billing schema" — overlap 0.04 with brief     |
```

## Data flow summary

1. Agents run → patrol hook records every event (incl. denials) to the audit log live.
2. After the run, `pd report` correlates audit log + transcripts + agent defs by `agent_id`.
3. Detectors run over the correlated per-agent action sequence.
4. A police report is emitted (JSON + markdown), one section per agent, offenses with evidence.

## Project layout

```
~/agent-pd/
  pd                       # CLI entry (or pyproject console_script `pd`)
  agent_pd/
    __init__.py
    hook.py                # patrol_hook implementation
    investigator.py        # gather + correlate
    detectors/
      permission_bypass.py
      out_of_scope.py
      redundant.py
      off_task.py
    report.py              # json + markdown rendering
    config.py              # load pd-rules.yaml
  pd-rules.yaml            # default rules
  tests/
  docs/superpowers/specs/2026-06-01-agent-pd-design.md
```

Python 3.11 (`python3` on this machine). Tests via `python3 -m pytest`.

## Implementation-time verification (must confirm before coding the parser)

Research returned conflicting signals on the exact on-disk transcript filename and
layout for subagents (`agent-<id>.jsonl` vs. per-session `<session-id>.jsonl` under
`~/.claude/projects/<encoded-path>/`). **First implementation step:** run a real
multi-subagent workflow, then inspect `~/.claude/projects/` and `~/.claude/pd/audit/`
to confirm: (a) the actual subagent transcript filename/location, (b) the real hook
JSON field names (`agent_id`, `agent_type`, `tool_input`, decision/reason for denials),
and (c) that `PermissionDenied` fires and carries enough to identify the agent. Adjust
the schemas above to match observed reality before writing detectors.

## Out of scope for v1 (explicit)

- Any intervention/blocking (kill/deny). Catch-and-report only.
- LLM-judge off-task and pointless-loop detection (v2, Anthropic API + prompt caching).
- A generic/pluggable adapter for non-Claude-Code agent logs (YAGNI until a 2nd source exists).
- Real-time alerting / dashboards.

## v2+ (noted, not built)

- LLM-judge detectors (off-task vs. brief, pointless loops) via Anthropic API (Haiku, cached),
  degrading gracefully when no API key is present.
- Optional live flagging (notify without blocking).
