"""Pure formatting for the live `pd watch` feed. No I/O — every function returns
strings so it is fully unit-testable without a terminal."""
import json
import os
from pathlib import Path

# severity -> (label, emoji, ansi-color-code)
SEVERITY_STYLE = {
    "critical": ("CRITICAL", "🚨", "1;31"),
    "high": ("HIGH", "⚠", "33"),
    "low": ("LOW", "●", "35"),
    "review": ("REVIEW", "👁", "34"),
    "info": ("INFO", "ℹ", "2;37"),
}
_SEV_ORDER = {"critical": 0, "high": 1, "low": 2, "review": 3, "info": 4}

# stable palette for per-agent coloring (cyan, green, yellow, magenta, blue, bright variants)
_AGENT_PALETTE = ["36", "32", "33", "35", "34", "31", "96", "92", "93", "95"]

# Show the real agent_type (no abbreviation) so the feed reads clearly. The tag is
# padded to this width in the feed so the tool/command columns line up.
_ABBREV = {}
_TAG_W = 22


class Style:
    def __init__(self, color: bool = True, emoji: bool = True):
        self.color = color
        self.emoji = emoji

    def paint(self, text: str, code: str) -> str:
        if not self.color or not code:
            return text
        return f"\033[{code}m{text}\033[0m"


def action_summary(tool_name: str, tool_input: dict, limit: int = 48) -> str:
    ti = tool_input or {}
    if tool_name == "Bash":
        s = str(ti.get("command", ""))
    elif tool_name == "Grep":
        s = str(ti.get("pattern", ""))
    elif tool_name == "Glob":
        s = str(ti.get("pattern") or ti.get("glob") or "")
    elif tool_name in ("Read", "Write", "Edit", "NotebookEdit"):
        s = str(ti.get("file_path") or ti.get("notebook_path") or "")
    elif tool_name == "WebFetch":
        s = str(ti.get("url", ""))
    elif tool_name == "WebSearch":
        s = str(ti.get("query", ""))
    else:
        # readable fallback for any other tool: prefer a human-meaningful field
        s = ""
        for k in ("query", "prompt", "description", "subject", "title",
                  "command", "url", "file_path", "content"):
            v = ti.get(k)
            if isinstance(v, str) and v.strip():
                s = v
                break
        if not s:
            s = json.dumps(ti, sort_keys=True)
    s = s.replace("\n", " ").replace("\r", " ")
    return s if len(s) <= limit else s[: limit - 1] + "…"


def badge(severity: str, style: Style) -> str:
    label, emoji, color = SEVERITY_STYLE.get(severity, (severity.upper(), "●", ""))
    text = f"{emoji} {label}" if style.emoji else label
    return style.paint(text, color)


def agent_color(agent_id: str) -> str:
    if not agent_id:
        return "37"   # grey for main/unknown
    idx = sum(ord(c) for c in agent_id) % len(_AGENT_PALETTE)
    return _AGENT_PALETTE[idx]


def agent_tag(agent_type: str, agent_id: str) -> str:
    t = _ABBREV.get(agent_type, agent_type) or "main"
    short = (agent_id or "")[:4] or "----"
    return f"{t}·{short}"


def _painted_tag(agent_type: str, agent_id: str, style: Style) -> str:
    return style.paint(agent_tag(agent_type, agent_id), agent_color(agent_id))


def format_banner(agent_type: str, agent_id: str, brief: str, style: Style,
                  session: str = None) -> str:
    arrow = "▸" if style.emoji else ">"
    tag = _painted_tag(agent_type, agent_id, style)
    sess = f"{style.paint('§' + session[:7], '2;37')} " if session else ""
    lines = [f"┌ {arrow} {sess}{tag}  started"]
    if brief:
        lines.append(f'│   brief: "{brief}"')
    lines.append("└─")
    return "\n".join(lines)


def home_rel(path: str) -> str:
    """Display a path home-relative (~/proj) so session lines stay short."""
    home = str(Path.home())
    if path and (path == home or path.startswith(home + os.sep)):
        return "~" + path[len(home):]
    return path


def session_identity_bits(project: str, title: str) -> list:
    """The displayable identity segments for a session — project then “title” —
    skipping whatever is unknown. Shared by the watch header, --all intros and list."""
    bits = []
    if project:
        bits.append(home_rel(project))
    if title:
        bits.append(f"“{title}”")
    return bits


def format_session_intro(session_id: str, project: str, title: str, style: Style) -> str:
    """One line introducing a session the first time it appears in the --all feed."""
    sess = style.paint("§" + (session_id or "")[:7], "2;37")
    return " " + " · ".join([sess] + session_identity_bits(project, title))


def _fmt_ts(ts) -> str:
    if not ts:
        return "--:--:--"
    s = str(ts)
    if "T" in s:                     # ISO 8601 -> take the HH:MM:SS part
        return s.split("T", 1)[1][:8]
    return s[:8]


def _worst(offenses) -> str:
    return min((o.severity for o in offenses), key=lambda s: _SEV_ORDER.get(s, 9))


def _offense_names(offenses) -> str:
    """De-duped offense names in first-seen order — what crime(s) this action committed."""
    seen, names = set(), []
    for o in offenses:
        if o.offense not in seen:
            seen.add(o.offense)
            names.append(o.offense)
    return " ".join(names)


def format_feed_line(ts, agent_type, agent_id, tool_name, tool_input, offenses,
                     style: Style, crimes_only: bool = False, verbose: bool = False,
                     session: str = None, width: int = 100) -> list:
    if crimes_only and not any(o.severity != "info" for o in offenses):
        return []   # nothing flagged, or only permitted (info) items — stay quiet
    plain_tag = agent_tag(agent_type, agent_id)
    tag = style.paint(plain_tag.ljust(_TAG_W), agent_color(agent_id))   # pad so columns align
    sess = f"{style.paint('§' + session[:7], '2;37')} " if session else ""
    sess_w = (len(session[:7]) + 2) if session else 0
    # Scale the command column to the terminal instead of a fixed 48, so wide terminals
    # aren't wasted and long commands aren't needlessly clipped.
    summary_limit = 400 if verbose else max(32, width - 58 - sess_w - _TAG_W)
    summary = action_summary(tool_name, tool_input, limit=summary_limit)
    if offenses:
        # severity badge + the offense name(s) so the crime is named on the line itself
        verdict = badge(_worst(offenses), style) + "  " + style.paint(_offense_names(offenses), "2;37")
    else:
        verdict = style.paint("✓" if style.emoji else "ok", "2;37")
    pad = "" if verbose else f"{'':<{max(0, summary_limit - len(summary))}}"
    main = f" {_fmt_ts(ts)}  {sess}{tag}  {tool_name:<8} {summary}{pad}  {verdict}"
    lines = [main]
    ev_limit = max(40, width - 13)   # "          └ " prefix is ~12 chars
    for o in offenses:
        reason = o.evidence if (verbose or len(o.evidence) <= ev_limit) else o.evidence[:ev_limit - 1] + "…"
        lines.append(style.paint(f"          └ {reason}", "2;37"))
    return lines


def _crime_count(crimes: dict) -> int:
    """Crimes exclude 'info' (permitted-but-flagged items are informational, not crimes)."""
    return sum(n for s, n in crimes.items() if s != "info")


def format_rap_sheet(entries: list, total_acts: int, style: Style) -> str:
    """One line per agent: tag · N acts · top tools · crimes (or 'clean'). entries are
    dicts: {tag, color, crimes:{sev:n}, acts:int, tools:{name:n}}."""
    total_crimes = sum(_crime_count(e["crimes"]) for e in entries)
    head = style.paint("RAP SHEET", "1")
    lines = [f" {head} — {len(entries)} agents · {total_crimes} crimes / {total_acts} acts"]
    # worst offenders first, then busiest
    ordered = sorted(entries, key=lambda e: (-_crime_count(e["crimes"]), -e["acts"]))
    for e in ordered:
        tag = style.paint(e["tag"], e["color"])
        if sum(e["crimes"].values()):
            bits = []
            for sev in ("critical", "high", "low", "review", "info"):
                n = e["crimes"].get(sev, 0)
                if n:
                    _, emoji, _ = SEVERITY_STYLE[sev]
                    bits.append(f"{n}{emoji}" if style.emoji else f"{n} {sev}")
            verdict = " ".join(bits)
        else:
            verdict = style.paint("clean", "2;37")
        top = sorted(e["tools"].items(), key=lambda kv: (-kv[1], kv[0]))[:3]
        tools = " ".join(f"{name}×{c}" for name, c in top) or "—"
        lines.append(f"   {tag}  {e['acts']:>3} acts  {tools:<34}  {verdict}")
    return "\n".join(lines)
