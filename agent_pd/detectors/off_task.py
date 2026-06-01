import re

from ..models import Offense

OFFENSE = "off_task"
SEARCH_TOOLS = {"Grep", "Glob", "WebSearch", "WebFetch"}
_WORD = re.compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "for", "on", "is", "this", "that"}


def _tokens(text: str) -> set:
    return {w for w in _WORD.findall((text or "").lower()) if w not in _STOP and len(w) > 1}


def _query_text(tool_input: dict) -> str:
    # Prefer the human-meaningful query/prompt over the URL: a WebFetch URL path
    # tokenizes into opaque slugs that rarely overlap the brief, so the fetch prompt
    # is what reflects intent. URL is the last-resort fallback.
    for k in ("pattern", "query", "prompt", "glob", "url"):
        if tool_input.get(k):
            return str(tool_input[k])
    return ""


def detect(record, rules) -> list:
    brief_tokens = _tokens(record.brief)
    if not brief_tokens:
        return []
    sev = rules.severity.get(OFFENSE, "review")
    threshold = rules.off_task_overlap_threshold
    out = []
    for a in record.actions:
        if a.tool_name not in SEARCH_TOOLS:
            continue
        q = _query_text(a.tool_input)
        qt = _tokens(q)
        if not qt:
            continue
        overlap = len(qt & brief_tokens) / len(qt)
        if overlap < threshold:
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "low",
                               f"{a.tool_name} '{q}' — overlap {overlap:.2f} with "
                               f"brief (low-confidence, for review)"))
    return out
