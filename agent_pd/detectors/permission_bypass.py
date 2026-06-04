import json
import re

from ..models import Offense
from ..permissions import is_permitted

OFFENSE = "permission_bypass"
# Escalation-pattern matching applies only to command-execution tools. Scanning the
# full input of file tools (Write/Edit) false-positives on file *content* that merely
# mentions a pattern — e.g. writing this detector's own escalation-pattern list.
# Denied calls are still flagged for any tool (a denied Write is a bypass attempt).
EXEC_TOOLS = {"Bash"}
_NOISE_KEYS = {"description"}  # free-text field; not part of the action — see redundant.py

_FLAGS = re.IGNORECASE


def _summ(tool_input: dict) -> str:
    return json.dumps(tool_input, sort_keys=True)


def _command_blob(tool_input: dict) -> str:
    # Match against the meaningful tool_input (command, sandbox flags, …) but exclude
    # the free-text `description` so a description merely mentioning a pattern is ignored.
    meaningful = {k: v for k, v in (tool_input or {}).items() if k not in _NOISE_KEYS}
    return json.dumps(meaningful)


def _first_match(blob: str, patterns) -> str | None:
    for p in patterns:
        try:
            if re.search(p, blob, _FLAGS):
                return p
        except re.error:
            # A user-supplied pattern that isn't valid regex: fall back to literal.
            if p.lower() in blob.lower():
                return p
    return None


def detect(record, rules) -> list:
    sev = rules.severity.get(OFFENSE, "high")
    info = rules.severity.get("permitted", "info")
    allow = getattr(record, "allow_rules", []) or []
    esc_patterns = rules.escalation_patterns
    nd_patterns = getattr(rules, "never_downgrade_patterns", []) or []
    out = []
    for a in record.actions:
        if a.decision == "deny":
            reason = f": {a.reason}" if a.reason else ""
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                               f"{a.tool_name}: {_summ(a.tool_input)} (denied{reason})"))
            continue
        if a.tool_name not in EXEC_TOOLS:
            continue
        blob = _command_blob(a.tool_input)

        # Tier 1: categorically dangerous — always critical, NEVER downgraded.
        nd = _first_match(blob, nd_patterns)
        if nd is not None:
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                               f"{a.tool_name}: matched never-downgrade pattern "
                               f"'{nd}' in {_summ(a.tool_input)}"))
            continue  # avoid double-reporting under the escalation tier

        # Tier 2: escalation — critical, downgradeable by a precise allow-rule.
        # Only a SPEC-BEARING rule (e.g. Bash(rm:*)) counts: a bare `Bash` grant is too
        # broad to excuse an escalation-tier command (a cwd-wipe, sudo, …), so we drop
        # bare tool-grants before testing permission.
        esc = _first_match(blob, esc_patterns)
        if esc is not None:
            precise = [r for r in allow if r.strip().endswith(")") and "(" in r]
            permitted = is_permitted("Bash", a.tool_input, None, precise, cwd=record.cwd)
            esev = info if permitted else sev
            note = " (permitted by allow-rule)" if permitted else ""
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, esev, "high",
                               f"{a.tool_name}: matched escalation pattern "
                               f"'{esc}' in {_summ(a.tool_input)}{note}"))
    return out
