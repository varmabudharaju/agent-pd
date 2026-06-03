# agent-pd — consistent main+subagent policing (scope engine + denial capture)

**Date:** 2026-06-02
**Status:** Design approved (brainstorm), pre-spec-review
**Scope:** Approach A — audit log as the single source of truth, a real `out_of_scope`
scope engine, and a fix for the broken permission-denial path.
**Supersedes nothing; extends:** `2026-06-01-agent-pd-design.md`

## Problem

When coding with Claude Code, the agent sometimes does things that aren't part of the
task: peeking into other folders, reading files outside the project, or attempting actions
that get permission-denied. The user wants a "police agent" that **consistently monitors
and flags** this — across **both** the main interactive agent and any subagents it spawns
— catch-and-report only, never blocking.

Three concrete gaps block that goal today:

1. **`pd report` can't see the main agent.** It builds records from subagent transcripts +
   audit *denials* only. Main-agent activity (`agent_id=""`) lives only as non-deny audit
   events, which the investigator throws away.
2. **The denial path is broken.** The hook set `decision` from a `permissionDecision`/
   `decision` field, but the real `PermissionDenied` payload carries no such field — the
   denial is implicit in the event name. So every denial was recorded with `decision=null`
   and dropped. The permission-bypass *denial* detector has never fired on real data.
   (The test suite hid this: fixtures fabricated the missing field.)
3. **`out_of_scope` is effectively a no-op.** It does nothing unless `scope_dirs` is set,
   and it only inspects file tools (Read/Write/Edit) — the common way Claude peeks
   elsewhere, Bash (`cat ../x`, `ls /etc`, `cd ..`, `find /`), is invisible.

## Goals / non-goals

**Goals**
- One consistent watchdog over the main agent **and** subagents, from one source.
- `out_of_scope` works out of the box: auto project-boundary + sensitive-path blocklist +
  optional allowlist, watching Bash navigation as well as file tools.
- Denied calls surface as critical offenses in both `pd report` and `pd watch`.
- Stay catch-and-report: hook remains logging-only, always exit 0.

**Non-goals (decided)**
- No real-time push/desktop alerts. Delivery is `pd watch` (live scanner) + `pd report`.
- No blocking/intervention.
- No main-agent `off_task` (needs a brief the main session lacks) — unchanged.

## Design

### 1. Audit log as the single source of truth (`gather()` refactor)

`LiveMonitor` (in `live.py`) already replays audit events into per-agent `AgentRecord`s,
attaches briefs from `meta.json`, and runs detectors. `pd report` reinvents a worse version
from transcripts. Collapse them:

- `gather(session_id)` reads every line from `~/.claude/pd/audit/<session>.jsonl` and
  replays them through a `LiveMonitor`, returning `list(mon.records.values())`.
- Each event with a `tool_name` → an `Action` grouped by `agent_id`. `agent_id == ""` is the
  **main agent** (record labeled `main`). Subagents get `brief`/`agent_type` from
  `meta.json`. Per-agent `cwd` comes from the event (needed by the scope engine).
- `run_detectors()` runs over those records unchanged.
- Transcript *action* parsing is **retired from the gather path** (`meta.json` still used for
  briefs). Each action now comes from exactly one source → no double-counting.

**Effects:** `pd report` sees main + every subagent from one source; the audit log finally
feeds the forensic report; `report` and `watch` share one accumulation engine.

**Limitation (documented):** sessions predating the hook (transcript-only, no audit file)
no longer appear in `pd report`. Acceptable — the hook records everything going forward.

**Error handling:** malformed/partial audit lines skipped; missing audit file → `[]`.

### 2. The `out_of_scope` scope engine

New pure helper module `scope.py`; `out_of_scope.py` rewritten to orchestrate it.

**Per-agent project root.** `base = cwd` (from the agent's audit events). `project_root` =
nearest ancestor containing `.git`, else `cwd`.

**Three classification rules**, applied to the resolved absolute path of every file access:

1. **Outside project (auto, default-on):** path outside `project_root` → `out_of_scope`,
   severity **high**. Evidence: `Read ../other/x.py (outside project <root>)`.
2. **Sensitive path (always, even inside project):** basename/path matches the blocklist →
   severity **critical**. Default blocklist: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`,
   `~/.config`, `.env`/`.env.*`, `*.pem`/`*.key`/`id_rsa`/`id_ed25519`/`*.p12`, `.netrc`/
   `.npmrc`/`.pypirc`/`.git-credentials`, `*.keychain`/`/Library/Keychains`. Evidence:
   `Read ~/.ssh/id_rsa (sensitive: ssh key)`. (Another repo's files fall out naturally —
   they're outside `project_root`.)
3. **Outside allowlist (opt-in):** if `scope_dirs` is set, an in-project path outside those
   dirs → severity **high** (today's behavior preserved). Empty `scope_dirs` → only rules
   1–2 apply.

**Bash blind spot.** `extract_paths(command)` pulls filesystem paths from Bash so
`cat ../secrets`, `ls /etc`, `cd ..`, `cp`, `find /` are policed like file-tool access.
Conservative to limit noise — a token is a path only if it (a) starts with `/`, `~`, `./`,
or `..`, **or** (b) is a positional arg to a known path-command (`cat ls cd cp mv less head
tail stat find du open code cmp diff`). Flags (`-x`), pipes/redirects, and URLs are ignored.
Each path is resolved against the agent's `cwd` and run through rules 1–3. `cd <dir>` is
special-cased so navigation out of the project is flagged.

**De-duplication.** Each distinct (tool-class, path, reason) is flagged **once per agent**
(`cat /etc/hosts` ×5 → one offense). Repeated identical calls remain the `redundant`
detector's job.

**Caveat (documented):** Bash path extraction is heuristic — misses paths built via shell
variables/`$(...)`/command substitution, can occasionally over-flag. File-tool checks stay
exact.

### 3. Permission-bypass fix

**3a. Reactivate denial capture.** In `hook.build_event`, after building the event:
```python
if ev["event"] == "PermissionDenied" and ev["decision"] is None:
    ev["decision"] = "deny"
```
The event firing *is* the denial signal (no payload field needed). Explicit
`permissionDecision`/`decision` is still read first (forward-compatible). Once
`decision=="deny"` is set, the existing chain already emits a **critical** offense in both
`report` and `watch`. `reason` captured if present; degrades to "denied" if absent.

**3b. Kill the escalation false positive.** `permission_bypass` matches escalation patterns
against the Bash **`command` field only** (not `json.dumps(tool_input)`, which included the
free-text `description`). Denied calls of any tool are still flagged regardless.

**Caveat:** the live `PermissionDenied` payload field names aren't confirmed against a real
denial (none in current logs). The event-name inference doesn't depend on payload fields; a
one-time live capture (per `NOTES.md`) would only refine the `reason` text.

### 4. New config keys (`pd-rules.yaml`)

All optional, sensible defaults:
- `sensitive_patterns: [...]` — the blocklist above, user-extendable.
- `project_boundary: true` — toggle the auto-outside-project rule (default on).
- `scope_dirs` — unchanged.
- Severity: `out_of_scope: high`; sensitive hits escalate to `critical` (configurable).

## Components & boundaries

| Unit | Purpose | Depends on |
|---|---|---|
| `hook.build_event` | normalize event; infer denial from event name | — |
| `investigator.gather` | replay audit → per-agent records (main + subs) | `live.LiveMonitor`, `meta.json` |
| `scope.py` | pure: `project_root`, `resolve`, `classify`, `extract_paths` | stdlib only |
| `detectors/out_of_scope` | orchestrate scope rules, emit offenses, de-dup | `scope.py`, `config.Rules` |
| `detectors/permission_bypass` | denial + escalation (command-field) offenses | `config.Rules` |
| `config` | load new keys with defaults | `pd-rules.yaml` |

## Testing strategy

TDD; tests fail before implementation, pass after. No network.

- **Realistic-payload fixtures:** shared module of payloads shaped as Claude Code actually
  sends them — notably a `PermissionDenied` with **no** decision field. Every hook-fed path
  is driven by these, not convenient hand-built objects.
- **Hook:** realistic `PermissionDenied` → `decision=="deny"`; `PostToolUse` → `None`;
  explicit field still honored; correct the fabricated fixture.
- **Investigator:** main (`agent_id=""`) + subagent events → `main` record + per-subagent
  records; denial surfaces; brief attached; no double-counting; missing/malformed tolerated;
  retire obsolete transcript-action tests.
- **Scope (`test_scope.py` + `test_out_of_scope.py`):** `project_root` git vs cwd; outside
  project flagged `high`; sensitive table-driven flagged `critical` even in-project;
  allowlist on/off; `extract_paths` for `cat`/`ls`/`cd`/`find` vs flags/pipes/URLs; de-dup;
  `project_boundary:false`.
- **Permission-bypass:** description-only `sudo` → no offense; real `sudo` → offense; denied
  call → critical.
- **Config:** new keys default + deep-merge; sensitive severity override.
- **Live/report regression:** unchanged user-visible output on the unified model.

## Data flow (after)

```
agents run (main + subs) → patrol hook → ~/.claude/pd/audit/<session>.jsonl
                                              │
   pd watch  ──tail──▶ LiveMonitor ──┐        │
                                     ├─ same engine ─▶ AgentRecords ─▶ detectors ─▶ output
   pd report ──replay file──▶ LiveMonitor ──┘
```

## Out of scope / deferred

See `KNOWN-GAPS.md` (judge API backend unverified, off_task flag-value extraction, redundant
re-reads, tool-result capture, allowlist tool-half, verdict cache, self-permissioning, etc.).
