import re

from ..models import Offense

OFFENSE = "off_task"
SEARCH_TOOLS = {"Grep", "Glob", "WebSearch", "WebFetch"}
# agents frequently search via the shell rather than the Grep tool; treat these Bash
# commands as searches too so off-topic shell searching isn't invisible.
_BASH_SEARCH = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "fd", "locate",
                "curl", "wget"}
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


def _bash_search_query(tool_input: dict) -> str:
    """If a Bash command is a search (grep/find/curl/...), return the command as its
    query text; otherwise empty (so non-search Bash like `git commit` is ignored)."""
    cmd = str((tool_input or {}).get("command", "")).strip()
    if not cmd:
        return ""
    parts = cmd.split()
    head = parts[0].rsplit("/", 1)[-1]
    if head == "sudo" and len(parts) > 1:        # look past a sudo prefix
        head = parts[1].rsplit("/", 1)[-1]
    return cmd if head in _BASH_SEARCH else ""


def _search_query(tool_name: str, tool_input: dict) -> str:
    if tool_name in SEARCH_TOOLS:
        return _query_text(tool_input)
    if tool_name == "Bash":
        return _bash_search_query(tool_input)
    return ""


def detect(record, rules) -> list:
    brief_tokens = _tokens(record.brief)
    if not brief_tokens:
        return []
    sev = rules.severity.get(OFFENSE, "review")
    threshold = rules.off_task_overlap_threshold
    out = []
    for a in record.actions:
        q = _search_query(a.tool_name, a.tool_input)
        if not q:
            continue
        qt = _tokens(q)
        if not qt:
            continue
        overlap = len(qt & brief_tokens) / len(qt)
        if overlap < threshold:
            shown = q if len(q) <= 60 else q[:59] + "…"
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "low",
                               f"{a.tool_name} '{shown}' — overlap {overlap:.2f} with "
                               f"brief (low-confidence, for review)"))
    return out
