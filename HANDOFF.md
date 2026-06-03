# agent-pd — Handoff

A "police department" for Claude Code subagents: a logging hook records every subagent
tool/permission event; a CLI audits those logs and reports rule offenses with evidence.
**Catch-and-report only — the hook never blocks an agent.**

- **Repo:** https://github.com/varmabudharaju/agent-pd (branch `master`)
- **Local:** `/Users/varma/agent-pd` · Python 3.11 (use `python3`) · CLI: `pd`
- **State at handoff:** 141 tests passing, working tree clean, all pushed.
- **Author policy:** all commits under `varma <sairam.vzf33@gmail.com>` — **no Co-Authored-By / no Claude or Anthropic attribution** in commits or PRs.

---

## How it works (mental model)

```
 SETUP            CAPTURE (automatic, all sessions)        READ (per session or --all)
 pd install-hook → hook fires on every tool call      →   pd report  (forensic)
   ↓                  ↓                                     pd watch   (live scanner)
 settings.json     ~/.claude/pd/audit/<session>.jsonl      pd judge   (opt-in LLM pass)
```

- **The hook is a dumb, crash-safe recorder.** It's registered globally in
  `~/.claude/settings.json` on PostToolUse / PermissionDenied / SubagentStart/Stop. On
  each event it appends one normalized line to a **per-session** audit file and always
  exits 0. So **all sessions are recorded concurrently**, each to its own file.
- **All the intelligence is in the reader.** `pd report` / `pd watch` correlate the
  audit log (+ subagent transcripts + `meta.json` briefs) into per-agent `AgentRecord`s
  and run the detectors. Zero LLM tokens — pure Python.
- **Denied calls only exist in the audit log** (Claude Code kills them before they hit
  the transcript), which is *why* the hook exists instead of just reading transcripts.

## The detectors

| Offense | Severity | How | Confidence |
|---|---|---|---|
| `permission_bypass` | critical | denied calls + escalation patterns (`sudo `, `dangerouslyDisableSandbox`…) in **Bash** commands only | high |
| `out_of_scope` | high | file OR Bash path outside the project (auto: git root or cwd), sensitive paths always (critical), or outside `scope_dirs` when set | high |
| `redundant` | low | exact-duplicate tool calls (ignores Bash `description` noise) | high |
| `off_task` | review | search term (incl. shell `grep`/`find`/`curl`) vs. brief word-overlap < threshold | **low — heuristic** |
| `self_permission` | critical | `Write`/`Edit`/`Bash` that writes a permission key into a `.claude/settings*.json` | high |
| `tool_not_allowed` | high | subagent uses a tool outside its declared `tools:` allowlist (`.claude/agents/<type>.md`) | high |

The three deterministic detectors are trustworthy and free. `off_task` is a noisy
heuristic — the **judge** (below) turns it into high-confidence verdicts.

**Permission-aware severity.** `out_of_scope` and escalation hits are downgraded to a quiet
`info` severity when the action matches a permission **allow-rule** the user configured
(`permissions.allow` in `~/.claude/settings.json` / project `.claude/settings.local.json`)
— authorized → info, unauthorized → full severity. `info` is not counted as a crime and is
hidden under `pd watch --crimes-only`. A denied call stays critical regardless. Allow-rules
are carried on each `AgentRecord` (loaded by `LiveMonitor` from the agent's cwd); detectors
never read settings files directly. See `agent_pd/permissions.py`.

## The off_task judge (`pd judge`) — opt-in, cost-capped

- Runs **only** the already-flagged `off_task` items (pre-filtered), **batched per agent**.
- **Dry-run by default** (prints item/agent/token estimate); `--run` actually calls.
- Two backends:
  - `--via-claude-code` → shells out to the headless `claude` CLI → **your Claude
    subscription, no API key**.
  - default → metered Anthropic API (needs `ANTHROPIC_API_KEY` + `pip install -e ".[judge]"`).
- Confirmed items become high-confidence Offenses (evidence = the model's reason); false
  positives are dropped. `--model haiku|sonnet|opus` (default haiku), `--max N` cap.

---

## Commands

```bash
pd install-hook                      # register the logging hook (one-time)
pd list                              # every recorded session

pd watch                             # live feed, one session (most recent)
pd watch --all                       # merged live feed across ALL sessions (§session tag)
pd watch --crimes-only               # quiet unless something's wrong
pd watch --verbose                   # full commands + reasons, no truncation
pd watch --session <id> --no-color --no-emoji

pd report                            # offense report, most recent session
pd report --session <id> --format md # md | json | both

pd judge                             # dry run (free) — shows the estimate
pd judge --run --via-claude-code     # judge on your subscription
pd judge --run --model sonnet --max 20   # metered API backend
```

## File map

```
agent_pd/
  hook.py           # patrol hook: stdin event -> audit log, always exit 0, crash-safe
  investigator.py   # gather(): correlate audit + transcripts + meta.json by agent_id
  detectors/
    __init__.py     # DETECTORS registry + run_detectors()
    permission_bypass.py  out_of_scope.py  redundant.py  off_task.py
  report.py         # render_json / render_markdown
  render.py         # live feed formatting: Style, badges, banner, feed line, rap sheet (pure)
  live.py           # LiveMonitor (state) + tail_events / tail_all_events + watch()
  judge.py          # opt-in off_task LLM judge (api + claude-code backends)
  config.py         # Rules + load_rules() (pd-rules.yaml deep-merged over defaults)
  models.py         # Action, AgentRecord, Offense dataclasses
  install_hook.py   # idempotent settings.json hook registration
  cli.py            # argparse: report/list/install-hook/watch/judge
tests/              # 141 tests, pure (no API key needed — judge uses injected fake clients)
pd-rules.yaml       # user-editable rules
docs/superpowers/   # specs + the original implementation plan
```

## Dev workflow

```bash
cd ~/agent-pd
pip install --user -e .          # core (zero runtime deps but PyYAML)
pip install --user -e ".[judge]" # + anthropic SDK (only for the API judge backend)
python3 -m pytest -q             # 141 tests
```

TDD throughout; detectors/render/live/judge are all unit-tested with no network.

---

## Known limitations (honest)

- **Workflow subagents have no brief.** Agents spawned by the Workflow tool leave no
  `meta.json` / transcript — they exist only as hook events. So their banners are bare
  and `off_task` can't run on them. Their **activity still shows** (feed + rap sheet).
- **No tool results in the feed.** The hook captures `tool_input`, not `tool_response`,
  so the feed shows what an agent *did*, not the outcome (exit code / output). Capturing
  results would risk bloating the audit log — deliberately left out.
- **`off_task` is inherently noisy** (word-overlap). The judge is the real fix; the
  detector is hard-labeled low-confidence "review" and never critical.
- **`PermissionDenied` decision** is now inferred from the event name (the hook sets
  `decision="deny"` for `PermissionDenied`), so denied calls are captured and flagged
  critical — no longer broken. The exact live payload *field names* still weren't
  confirmed against a real denial (see `NOTES.md`); `hook.py` reads fields defensively
  (camelCase + snake_case), so this refines but doesn't block.
- **Sessions that predate the hook won't appear in `pd report`.** `gather()` reads only
  the audit log (single source of truth covering main + subagents), so a session with no
  `~/.claude/pd/audit/<session>.jsonl` is invisible to `pd report`. Intended tradeoff.
- **Concurrent appends:** multiple subagents in one session append to the same file;
  a >4 KB tool input could in theory interleave a line. Harmless — the reader skips any
  malformed/partial line.
- **`pd watch` default "most recent"** can flip between two concurrently-active sessions;
  use `--session` or `--all`.

## Backlog / next steps (discussed, not built)

1. **Capture tool results/outcomes in the hook** (success/failure, output size) → richer
   feed showing what each action *did*. Watch audit-log size.
2. **`pd summary <session>`** — per-agent digest (files touched, time span, tool histogram).
3. **`out_of_scope` tool-allowlist half** — flag tools outside an agent's declared
   `tools:` allowlist (needs reading `.claude/agents/<type>.md` frontmatter). v2.
4. **Verdict disk cache for the judge** — skip re-judging identical (brief, search) pairs.
5. **Confirm the live `PermissionDenied` hook payload** field names (one-time capture).

## Reset to a clean slate (optional)

```bash
rm ~/.claude/pd/audit/*.jsonl   # clear all recorded audit logs; they repopulate as sessions run
```

---

*Design specs and the original 12-task implementation plan are under
`docs/superpowers/specs/` and `docs/superpowers/plans/`.*
