# agent-pd

A police department for Claude Code subagents. A logging-only hook records every
subagent tool/permission event; the `pd` CLI correlates those logs with subagent
transcripts and reports rule offenses with quoted evidence. Catch-and-report only —
the hook never blocks an agent.

## Install

```bash
pip install --user -e .
pd install-hook          # registers the logging hook in ~/.claude/settings.json
```

## Use

```bash
pd list                  # list sessions with recorded activity
pd report                # report offenses for the most recent session
pd report --session <id> --format md
pd report --verbose            # full evidence + files-touched per agent
pd report --agent <id|main>    # focus one agent: digest + every action it took
pd watch                 # live "police scanner" feed of agent activity + crimes
pd verify [--session ID] [--all]
                         # check the audit-log hash-chain — detects tampering/truncation
                         # (✓ intact / ✗ TAMPER DETECTED or TRUNCATED, rc 2). Set
                         # PD_AUDIT_KEY for HMAC-keyed integrity an off-key attacker can't forge.
pd compact [--session ID] [--prune-older-than DAYS] [--dry-run]
                         # gzip old session logs (<sid>.jsonl → <sid>.jsonl.gz), skipping the
                         # most-recently-modified (active) session. Lossless: every field stays
                         # inline, so detection over a compacted session is identical to the raw
                         # session. --prune-older-than DAYS optionally deletes compacted sessions
                         # older than N days (default: keep everything, for autopsy bookkeeping).
pd sink push [--session ID] [--all]
                         # forward un-sent chained audit events off-host to an append-only sink,
                         # so retroactive local deletion can't reach what already shipped
                         # (incremental + idempotent; retries on failure)
pd sink status [--session ID] [--all]
                         # show forwarded/last per session; flags "remote ahead" (a sign the
                         # local log was truncated/tampered)
```

**Off-host sink config (env).** `PD_SINK_TYPE=file|http`, then `PD_SINK_PATH=...` (file
backend) or `PD_SINK_URL=...` (http backend); `PD_SINK_TOKEN=...` is the **env-only** bearer
token for the http backend (never put it in a config file). For a remote http sink always use
`https://` — the token is refused over cleartext to a non-loopback host. See SECURITY.md for
the honest framing (append-only-IF-deployed-correctly; doesn't stop forging or hook-disable).

`pd report` replays the session audit log through the same engine `pd watch` uses, so it
covers **both** the main agent (shown as `main`) and its subagents from one source.
Denied calls (`PermissionDenied`) are captured and flagged critical. Each agent header
shows a one-line digest (acts · time span · top tools · crime badges), and the main agent
is named by its project and session — clean agents are summarized too.

## Live view: `pd watch`

A real-time feed of what your agents are doing and which rules they're breaking, as it
happens (it follows the audit log the hook writes). Each agent gets a stable color and a
banner showing its assigned brief; every action is a feed line with a severity badge,
and a live rap-sheet footer tallies crimes per agent.

```
┌ ▸ Explore · a93c  started
│   brief: "find all callers of authenticate()"
└─
 12:01:03  Explore·a93c   Grep     "authenticate\("            ✓
 12:01:06  gp·a55d        Bash     sudo rm -rf /tmp/cache      🚨 CRITICAL  permission_bypass
                                    └ escalation pattern 'sudo ' in command
 RAP SHEET   Explore·a93c: clean   ·   gp·a55d: 1🚨   ·   total 1 crimes / 2 acts
```

Flags: `--all` (merge the live feed across **every** session — each line tagged with
`§<session>` so you can tell them apart), `--crimes-only` (hide clean actions),
`-v`/`--verbose` (full commands + full offense reasons, no truncation), `--no-color`,
`--no-emoji` (plain terminals / SSH), `--session <id>` (default: most-recently-active
session). Ctrl-C prints a final rap sheet. Zero extra dependencies — ANSI only.

The hook records **all** sessions concurrently (one `~/.claude/pd/audit/<session>.jsonl`
per session). `pd watch` shows one session at a time by default; `pd watch --all` merges
them; `pd list` enumerates every recorded session.

**On-disk layout:** `audit/<sid>.jsonl` (live capture, hook-written) and
`audit/<sid>.jsonl.gz` (compacted). Reads (`pd report`, `pd watch`) transparently handle both.

## Offenses (v1, deterministic)

| Offense           | Detection                                   | Confidence |
|-------------------|---------------------------------------------|------------|
| permission_bypass | denied calls + escalation patterns          | high       |
| out_of_scope      | file OR Bash path outside the project (auto), sensitive paths always (critical), or outside `scope_dirs` | high |
| redundant         | exact-duplicate tool calls                  | high       |
| off_task          | low query/brief token overlap (heuristic)   | low/review |

Configure via `pd-rules.yaml` (see the file for keys). The deterministic detectors cost
zero tokens. `off_task` is a low-confidence "for review" heuristic — to turn its noisy
flags into trustworthy verdicts, use the opt-in judge below.

**Permission-aware severity.** `out_of_scope` and escalation hits are downgraded to a
quiet `info` severity when the action matches a permission **allow-rule** you configured
(Claude Code's `permissions.allow` in `~/.claude/settings.json` or the project
`.claude/settings.local.json`) — *authorized → info, unauthorized → full severity*. `info`
is not counted as a crime and stays quiet under `pd watch --crimes-only`. A denied call
(`permission_bypass`) stays critical regardless — a denial is unpermitted by definition.

## Optional: the off_task judge (`pd judge`)

An opt-in LLM pass that reads each agent's brief and its flagged searches and reasons
about relevance, turning low-confidence `off_task` flags into high-confidence verdicts
(or dropping them as false positives). Designed to cost almost nothing:

- **Opt-in** — never runs in the hook or `pd watch`.
- **Pre-filtered + batched** — only the already-flagged `off_task` items, one API call
  per agent.
- **Dry-run by default** — `pd judge` just prints an estimate (items, agents, ≈tokens).
  Add `--run` to actually call the API.
- **Cheap by default** — `--model haiku` (default) / `sonnet` / `opus`; `--max N` caps it.

Two backends:

```bash
# A) Via your Claude subscription — no API key, uses the `claude` CLI:
pd judge                            # dry run
pd judge --run --via-claude-code    # judge on your subscription

# B) Via the metered Anthropic API (needs a key):
pip install -e ".[judge]"           # optional anthropic SDK
export ANTHROPIC_API_KEY=...
pd judge --run                      # ~a fraction of a cent on Haiku
pd judge --run --model sonnet --max 20
```

`--via-claude-code` shells out to the headless `claude` CLI, so it's billed to your
Claude subscription (the same auth Claude Code uses) rather than the pay-per-token API.
With neither a `claude` CLI nor API credentials available, `pd judge --run` degrades
gracefully.

## License

[Apache License 2.0](LICENSE) © varma. Free to use, modify, and distribute (including
commercially); retain the copyright and license notice. Includes a patent grant.
