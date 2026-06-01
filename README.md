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
pd watch                 # live "police scanner" feed of agent activity + crimes
```

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

Flags: `--crimes-only` (hide clean actions), `--no-color`, `--no-emoji` (plain
terminals / SSH), `--session <id>` (default: most-recently-active session). Ctrl-C
prints a final rap sheet. Zero extra dependencies — ANSI only.

## Offenses (v1, deterministic)

| Offense           | Detection                                   | Confidence |
|-------------------|---------------------------------------------|------------|
| permission_bypass | denied calls + escalation patterns          | high       |
| out_of_scope      | file path outside `scope_dirs`              | high       |
| redundant         | exact-duplicate tool calls                  | high       |
| off_task          | low query/brief token overlap (heuristic)   | low/review |

Configure via `pd-rules.yaml` (see the file for keys). Off-task is a low-confidence
"for review" heuristic; a real LLM judge is planned for v2.
