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
```

## Offenses (v1, deterministic)

| Offense           | Detection                                   | Confidence |
|-------------------|---------------------------------------------|------------|
| permission_bypass | denied calls + escalation patterns          | high       |
| out_of_scope      | file path outside `scope_dirs`              | high       |
| redundant         | exact-duplicate tool calls                  | high       |
| off_task          | low query/brief token overlap (heuristic)   | low/review |

Configure via `pd-rules.yaml` (see the file for keys). Off-task is a low-confidence
"for review" heuristic; a real LLM judge is planned for v2.
