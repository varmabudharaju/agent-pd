"""Pure per-agent summary helpers for pd report: a human label and an activity digest.
No I/O. Used by report.render_markdown."""
import os
from collections import Counter

from .render import SEVERITY_STYLE

_SEV_DIGEST_ORDER = ("critical", "high", "low", "review", "info")


def agent_label(record, session_id=None) -> str:
    if not record.agent_id:                        # the main (top-level) agent
        label = "main"
        proj = os.path.basename((record.cwd or "").rstrip("/"))
        if proj:
            label += f" · {proj}"
        if session_id:
            label += f" (session {session_id[:7]})"
        return label
    return f"{record.agent_type or '?'} ({record.agent_id[:8]}…)"


def _hhmm(ts) -> str:
    s = str(ts)
    return s.split("T", 1)[1][:5] if "T" in s else s[:5]


def agent_digest(record, agent_offenses) -> dict:
    tss = [a.ts for a in record.actions if a.ts]
    files, seen = [], set()
    for a in record.actions:
        ti = a.tool_input or {}
        p = ti.get("file_path") or ti.get("notebook_path")
        if p and p not in seen:
            seen.add(p)
            files.append(p)
    return {
        "acts": len(record.actions),
        "first": _hhmm(min(tss)) if tss else None,
        "last": _hhmm(max(tss)) if tss else None,
        "tools": Counter(a.tool_name for a in record.actions if a.tool_name),
        "files": files,
        "crimes": Counter(o.severity for o in agent_offenses),
    }


def format_digest_line(digest, emoji=True) -> str:
    bits = [f"{digest['acts']} acts"]
    if digest["first"]:
        bits.append(digest["first"] if digest["first"] == digest["last"]
                    else f"{digest['first']}–{digest['last']}")
    top = sorted(digest["tools"].items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    if top:
        bits.append(" ".join(f"{n}×{c}" for n, c in top))
    crimes = digest["crimes"]
    if sum(crimes.values()):
        cb = []
        for sev in _SEV_DIGEST_ORDER:
            n = crimes.get(sev, 0)
            if n:
                _, em, _ = SEVERITY_STYLE.get(sev, (sev, "•", ""))
                cb.append(f"{n}{em}" if emoji else f"{n} {sev}")
        bits.append(" ".join(cb))
    else:
        bits.append("clean")
    return " · ".join(bits)
