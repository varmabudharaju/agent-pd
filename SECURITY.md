# Security posture

This document is an honest account of what agent-pd does, what it detects, and — just as
important — where it stops. Read it before you rely on pd to keep an agent in line.

## What agent-pd is

agent-pd is a **catch-and-report watchdog** for Claude Code agent activity — both the main
interactive agent and its subagents. A logging-only hook records every tool/permission
event to an audit log; the `pd` CLI replays that log through a set of detectors and reports
offenses with quoted evidence.

It **detects and reports. It does not block or prevent.** The hook is logging-only and
**always exits 0** — it never denies a tool call, never intervenes, never sandboxes. Think
of it as a flight recorder and a police scanner, not a firewall. If you need to *stop* an
action, that has to happen elsewhere (Claude Code's own permission prompts, an OS sandbox).

## Threat model — what it detects

| What | Detector | Trust |
|---|---|---|
| File access outside the project, incl. via Bash, interpreter one-liners (`bash -c`, `python -c`, `node -e`), single-level `$VAR`, and best-effort symlinks | `out_of_scope` | deterministic |
| Access to sensitive paths (`~/.ssh`, `~/.aws`, `~/.claude` incl. the audit dir, `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/ssh`, `/root`, shell history…) | `out_of_scope` (critical) | deterministic |
| Permission-bypass / dangerous commands, two-tier (see below) + denied calls | `permission_bypass` | deterministic |
| An agent modifying **its own control files** — `.claude/settings*.json`, `.claude/agents/*.md`, `pd-rules*.yaml` — via any method (Write/Edit/NotebookEdit, or Bash cp/mv/tee/sed/python/base64/redirect), regardless of content | `self_permission` | deterministic |
| A subagent using a tool outside its declared `tools:` allowlist | `tool_not_allowed` | deterministic |
| A query that looks unrelated to the agent's brief | `off_task` | **heuristic / advisory** |

The **deterministic** detectors are trustworthy: they fire on facts in the log, cost zero
tokens, and don't guess. `off_task` is an **advisory** word-overlap heuristic — it is
hard-labeled low-confidence and is meant to be confirmed by `pd judge` (an opt-in LLM pass),
not trusted on its own.

## Permission model

Offenses that match the user's `permissions.allow` rules (from `~/.claude/settings.json` or
the project `.claude/settings.local.json`) are downgraded to **informational** — a permitted
action is an FYI, not a crime. The matching mirrors **Claude Code's own semantics**:
shell-operator splitting (a `Bash(git:*)` rule does **not** license `git status && rm -rf ~`),
command-substitution and backtick extraction, redirect targets treated as a separate
authorization (a command rule can't license `> ~/.ssh/authorized_keys`), word-boundary
prefix matching (`npm install:*` ≠ `npm installmalware`), and gitignore-style globs
(`*` does not cross `/`, `**` does). Ambiguity resolves **conservatively → not permitted**.

Two categories are **never** downgraded, no matter what allow-rule you write:

- **Sensitive-path access** — reading/writing `~/.ssh`, credentials, the audit dir, etc.
- **Categorically-catastrophic commands** — `rm -rf /` (incl. long-flag and quoted forms),
  `rm -rf ~`/`$HOME`, `--no-preserve-root`, fork bombs, `dd of=/dev/…`, `mkfs`, `curl | sh`.

A denied call (`PermissionDenied`) always stays critical — a denial is unpermitted by
definition.

## Known limitations (read this)

pd **raises the bar; it is not a sandbox.** A determined adversary using obfuscation or
indirection can evade static detection. Calibrate your trust accordingly.

- **Obfuscation / indirection evades static detection.** Multi-level `$VAR` chains
  (`A=/etc/shadow; B=$A; cat $B` — only single-level expansion is followed), `$IFS` /
  word-split tricks, two-step download-then-exec (`curl -o f url; sh f`), base64- or
  eval-assembled commands, and dynamically-constructed paths can slip past.
- **Only Write/Edit/NotebookEdit and Bash are inspected for control-file writes.** A
  filesystem MCP tool with a different shape could write `.claude/settings.json` without
  tripping `self_permission`.
- **Symlink resolution is best-effort** — the symlink must exist on disk at analysis time.
- **`off_task` is heuristic** (word-overlap); use `pd judge` for trustworthy verdicts.
  `~/.config` sensitivity is broad and can be noisy.
- **No cryptographic integrity on the audit log.** An agent with Bash can delete or forge
  `~/.claude/pd/audit/*.jsonl`. pd flags access to the audit directory as sensitive-critical
  (it **detects** the attempt) but does **not prevent** tampering, and there is no
  tamper-evident (HMAC / hash-chain / append-only) log. This is the most significant
  architectural gap and is documented as future work in `KNOWN-GAPS.md`.

## Privacy

The audit log stores the **full tool inputs** — file contents and Bash commands — which
**may include secrets** (tokens, keys, passwords) in **plaintext**, under
`~/.claude/pd/audit/`. It lives **outside your repo**, so it won't be committed by accident,
but treat it like any other sensitive local file. `pd compact` gzips old logs, which
**compresses but does not encrypt** them. There is no remote upload — everything stays on
your machine. To clear it: `rm ~/.claude/pd/audit/*.jsonl` (logs repopulate as sessions run).

## Reporting issues

Found a detection gap or a security bug? Please open a GitHub issue.
