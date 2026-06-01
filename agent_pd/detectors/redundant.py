import json

from ..models import Offense

OFFENSE = "redundant"
# Fields that describe an action rather than define it — two calls that differ only in
# these are still the same action (e.g. Bash's free-text `description`).
_NOISE_KEYS = {"description"}


def _key_input(tool_input: dict) -> str:
    meaningful = {k: v for k, v in (tool_input or {}).items() if k not in _NOISE_KEYS}
    return json.dumps(meaningful, sort_keys=True)


def detect(record, rules) -> list:
    sev = rules.severity.get(OFFENSE, "low")
    counts = {}
    out = []
    for a in record.actions:
        key = (a.tool_name, _key_input(a.tool_input))
        counts[key] = counts.get(key, 0) + 1
        if counts[key] == 2:   # report once, on first repeat
            payload = key[1] if len(key[1]) <= 120 else key[1][:120] + "…"
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                               f"duplicate {a.tool_name}: {payload}"))
    return out
