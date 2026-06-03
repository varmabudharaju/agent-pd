"""Flags a subagent using a tool outside its declared `tools:` allowlist. The allowlist is
carried on record.tool_allowlist (loaded by LiveMonitor from the agent definition); None
means unrestricted (built-in agents, or no `tools:` key) and is never flagged."""
from ..models import Offense

OFFENSE = "tool_not_allowed"


def detect(record, rules) -> list:
    allow = getattr(record, "tool_allowlist", None)
    if allow is None:
        return []
    sev = rules.severity.get(OFFENSE, "high")
    out, seen = [], set()
    for a in record.actions:
        t = a.tool_name
        if not t or t in allow or t in seen:
            continue
        seen.add(t)
        out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                           f"used {t} — not in declared allowlist {sorted(allow)}"))
    return out
