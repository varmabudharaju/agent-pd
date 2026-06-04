import json

from ..models import Offense
from ..permissions import is_permitted

OFFENSE = "permission_bypass"
# Escalation-pattern matching applies only to command-execution tools. Scanning the
# full input of file tools (Write/Edit) false-positives on file *content* that merely
# mentions a pattern — e.g. writing this detector's own escalation-pattern list.
# Denied calls are still flagged for any tool (a denied Write is a bypass attempt).
EXEC_TOOLS = {"Bash"}
_NOISE_KEYS = {"description"}  # free-text field; not part of the action — see redundant.py


def _summ(tool_input: dict) -> str:
    return json.dumps(tool_input, sort_keys=True)


def detect(record, rules) -> list:
    sev = rules.severity.get(OFFENSE, "high")
    info = rules.severity.get("permitted", "info")
    allow = getattr(record, "allow_rules", []) or []
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
        meaningful = {k: v for k, v in (a.tool_input or {}).items() if k not in _NOISE_KEYS}
        blob = json.dumps(meaningful).lower()
        for p in patterns:
            if p.lower() in blob:
                permitted = is_permitted("Bash", a.tool_input, None, allow,
                                         cwd=record.cwd)
                esev = info if permitted else sev
                note = " (permitted by allow-rule)" if permitted else ""
                out.append(Offense(record.agent_id, record.agent_type, OFFENSE, esev, "high",
                                   f"{a.tool_name}: matched escalation pattern "
                                   f"'{p}' in {_summ(a.tool_input)}{note}"))
                break
    return out
