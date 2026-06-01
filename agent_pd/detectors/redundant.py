import json

from ..models import Offense

OFFENSE = "redundant"


def detect(record, rules) -> list:
    sev = rules.severity.get(OFFENSE, "low")
    counts = {}
    out = []
    for a in record.actions:
        key = (a.tool_name, json.dumps(a.tool_input, sort_keys=True))
        counts[key] = counts.get(key, 0) + 1
        if counts[key] == 2:   # report once, on first repeat
            payload = key[1] if len(key[1]) <= 120 else key[1][:120] + "…"
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                               f"duplicate {a.tool_name}: {payload}"))
    return out
