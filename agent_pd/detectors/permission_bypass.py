import json

from ..models import Offense

OFFENSE = "permission_bypass"
# Escalation-pattern matching applies only to command-execution tools. Scanning the
# full input of file tools (Write/Edit) false-positives on file *content* that merely
# mentions a pattern — e.g. writing this detector's own escalation-pattern list.
# Denied calls are still flagged for any tool (a denied Write is a bypass attempt).
EXEC_TOOLS = {"Bash"}


def _summ(tool_input: dict, limit: int = 120) -> str:
    s = json.dumps(tool_input, sort_keys=True)
    return s if len(s) <= limit else s[:limit] + "…"


def detect(record, rules) -> list:
    sev = rules.severity.get(OFFENSE, "high")
    patterns = rules.escalation_patterns
    out = []
    for a in record.actions:
        if a.decision == "deny":
            reason = f": {a.reason}" if a.reason else ""
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                               f"{a.tool_name}: {_summ(a.tool_input)} (denied{reason})"))
            continue
        if a.tool_name not in EXEC_TOOLS:
            continue
        cmd = str((a.tool_input or {}).get("command", "")).lower()
        for p in patterns:
            if p.lower() in cmd:
                out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                                   f"{a.tool_name}: matched escalation pattern "
                                   f"'{p}' in {_summ(a.tool_input)}"))
                break
    return out
