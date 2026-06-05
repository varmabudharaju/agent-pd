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
| Access to sensitive paths (`~/.ssh`, `~/.aws`, `~/.claude` incl. the audit dir, `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/ssh`, `/root`, shell history…) **and credential files by name** (`.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `.netrc`, `.git-credentials`, …) — matched by basename for **any** Bash command, so `grep KEY .env` / `base64 .env` / `tar … .env` are caught, not just `cat`/`head` | `out_of_scope` (critical) | deterministic |
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
definition. The denial is inferred from the event name, which the hook reads in both
snake_case (`hook_event_name`) and camelCase (`hookEventName`), so a denied call cannot
slip through as an unrecognized event and go unflagged.

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
- **The audit log is tamper-*evident*, not tamper-*proof*.** pd now hash-chains the log so
  corruption, truncation, reordering, and naive edits are caught by `pd verify` (see below).
  But an agent with Bash runs as the same user: it can read the log, the head anchor, and
  (usually) `PD_AUDIT_KEY`, so a determined attacker can re-chain the whole log after
  tampering and still pass `pd verify`. The off-host sink (`pd sink push`, below) closes the
  *retroactive-deletion* half of this — events already shipped off-host can't be made to
  disappear — but does not stop a same-user agent from forging entries or disabling the hook.

## Audit-log integrity

Every audit event carries a `seq` (monotonic per session) and a `chain` value:
`chain = sha256(prev_chain + canonical(event))`, or **HMAC-SHA256** if the environment
variable `PD_AUDIT_KEY` is set. The hook computes this under a per-session file lock (safe
under parallel subagents) and records a `<sid>.head.json` anchor pointing at the chain tail.
The hook stays crash-safe: it always exits 0, never loses an event, and a head-write failure
is benign (the next event re-anchors).

**`pd verify [--session ID] [--all] [--audit-dir ...]`** recomputes the chain and reports:

- `✓ chain intact — N event(s) verified` (exit 0)
- `✗ TAMPER DETECTED — chain breaks at seq X (bad-link | seq-gap | unchained-after-chain)`
  (exit 2)
- `✗ TRUNCATED — head recorded seq H but log ends at seq L` (exit 2)
- `✗ TAMPER DETECTED — head anchor does not match the log tail (chain was rewritten)`
  (exit 2)
- `⚠ no integrity data — legacy session` (exit 0, for sessions recorded before this feature)

Exit code **2** on any tamper or truncation makes it scriptable; `--all` checks every
session. The chain verifies across `pd compact` — it holds over the gzipped log because the
canonical form is round-trip stable.

**What it detects:** in-place edits, reordering, mid-log deletion, tail truncation, inserted
unchained lines, and — with `PD_AUDIT_KEY` set — edits by someone without the key (an
attacker who can read the log but not the key can no longer forge a valid chain).

**The honest framing:** this is tamper-**evident**, not tamper-**proof**. The adversary we
care about is a same-user agent with Bash, which can read the log, the head file, and often
`PD_AUDIT_KEY` itself; such an attacker can re-chain the entire log after editing and pass
`pd verify`. What the hash-chain reliably catches is corruption, truncation, reordering, and
naive/most edits (including an attacker who edits but forgets to fix the head anchor or a
downstream link) — and it gives an autopsy a real trust signal. To raise the bar past
"locally defeatable," ship the chained events to an **off-host, append-only sink** the
audited agent can't reach — see the next subsection.

**Recommendation:** run `pd verify` before you trust a log in an autopsy. For stronger
deployments, set `PD_AUDIT_KEY` in an environment the audited agent **cannot read** — keying
the chain is only as strong as the secrecy of the key.

## Audit-log integrity — off-host sink

The hash-chain makes the local log tamper-**evident** but **locally defeatable**: a same-user
agent can re-chain the whole file. The off-host sink forwards each chained event to a
destination outside the host, so a later local rewrite cannot reach the events already
shipped — the off-host copy is the witness.

**`pd sink push [--session ID] [--all]`** forwards only the un-sent chained events for a
session (those whose `seq` exceeds the last-forwarded seq) and advances the per-session state
(`<sid>.sink`) only after the sink durably accepts them. It is **incremental and idempotent**:
on success it never re-sends; on failure it does **not** advance, so the same events retry on
the next push — no skip, no double-send. Only chained events are forwarded; legacy/pre-chain
events (no `seq`) are intentionally skipped.

**`pd sink status [--session ID] [--all]`** shows `forwarded/last` per session. When
`forwarded > last` it flags **"⚠ remote ahead"** — more events were shipped off-host than
remain in the local log, i.e. a local-truncation/tamper signal.

**The hook is untouched.** There is no network on the per-tool-call hot path; the local audit
log *is* the spool. Run `pd sink push` on a schedule or from a Stop hook to drain it.

**Backends (stdlib only):**

- **file** — appends NDJSON to a path. Point it at a different mount, a WORM volume, or an
  append-only dir (`chattr +a`). The append-only guarantee is the operator's responsibility.
- **http** — POSTs NDJSON to your collector, with `Authorization: Bearer $PD_SINK_TOKEN` when
  a token is set.

**Config.** A `sink` section in the rules file (`type: file|http`, `url`, `path`, `timeout`),
with env overrides `PD_SINK_TYPE` / `PD_SINK_URL` / `PD_SINK_PATH` / `PD_SINK_TIMEOUT`. The
secret token is **env-only** (`PD_SINK_TOKEN`) and is deliberately ignored if placed in a
config file, so it never lives in a checked-in / world-readable file.

**Transport security.** TLS certificates are verified by default; the token is **refused over
cleartext `http://` to a non-loopback host** (use `https://`, or unset the token), and
**redirects are not followed** (a 3xx could re-send the `Authorization` header to another host
= a cross-host credential leak). Serialization failures map to a clean error, never a crash.

**The honest framing.** The sink upgrades integrity from "tamper-evident, locally defeatable"
to **"retroactive deletion/alteration of genuine events is prevented"** — but *only* if the
destination is genuinely append-only and the write credential cannot delete or modify what's
already there. That is a **deployment requirement** (server-enforced); pd cannot guarantee it.
It is still **not fully tamper-proof**, and the same "raises the bar, not a sandbox" framing
applies:

- The same-user agent holds the write credential, so it can **forge** entries into the sink.
- It can **disable the hook** so nothing is sent (a gap, not a deletion).

What you do get: a damning event already shipped off-host can't be made to disappear, and
`pd verify` / `integrity.verify_events` can prove local↔off-host divergence.

**Recommendation:** run `pd sink push` on a schedule (or a Stop hook); use an append-only
collector with **write-only, non-deleting** credentials; set `PD_SINK_TOKEN` only in an
environment the audited agent **cannot read**; always use `https://` for remote sinks.

## Privacy

The audit log stores the **full tool inputs** — file contents and Bash commands — which
**may include secrets** (tokens, keys, passwords) in **plaintext**, under
`~/.claude/pd/audit/`. It lives **outside your repo**, so it won't be committed by accident,
but treat it like any other sensitive local file. `pd compact` gzips old logs, which
**compresses but does not encrypt** them. There is no remote upload — everything stays on
your machine. To clear it: `rm ~/.claude/pd/audit/*.jsonl` (logs repopulate as sessions run).

## Reporting issues

Found a detection gap or a security bug? Please open a GitHub issue.
