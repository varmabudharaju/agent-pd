import json
from dataclasses import asdict

from .summary import agent_label, agent_digest, format_digest_line
from .render import action_summary, _fmt_ts

_SEV_ORDER = {"critical": 0, "high": 1, "low": 2, "review": 3, "info": 4}
_MD_EVIDENCE_LIMIT = 120


def render_json(offenses: list) -> str:
    return json.dumps([asdict(o) for o in offenses], indent=2)


def _ev_cell(evidence: str, verbose: bool) -> str:
    # truncate the raw evidence first, then escape — so we never clip a "\|" pair
    if not verbose and len(evidence) > _MD_EVIDENCE_LIMIT:
        evidence = evidence[:_MD_EVIDENCE_LIMIT] + "…"
    return evidence.replace("|", "\\|")


def _offense_table(offs: list, verbose: bool) -> list:
    lines = ["", "| severity | offense | confidence | evidence |",
             "|----------|---------|------------|----------|"]
    for o in sorted(offs, key=lambda o: _SEV_ORDER.get(o.severity, 9)):
        lines.append(f"| {o.severity} | {o.offense} | {o.confidence} | {_ev_cell(o.evidence, verbose)} |")
    return lines


def _matches(record, only_agent: str) -> bool:
    if only_agent == "main":
        return record.agent_id == ""
    return bool(record.agent_id) and record.agent_id.startswith(only_agent)


def _render_focus(matches: list, by_agent: dict, session_id) -> str:
    out = []
    for rec in matches:
        offs = by_agent.get(rec.agent_id, [])
        digest = agent_digest(rec, offs)
        out.append(f"## {agent_label(rec, session_id)}")
        if rec.brief:
            out.append(f'assigned: "{rec.brief}"')
        out.append(f"_{format_digest_line(digest)}_")
        if digest["files"]:
            out.append(f"files: {', '.join(digest['files'])}")
        if offs:
            out += _offense_table(offs, verbose=True)
        out += ["", "### actions"]
        for a in rec.actions:
            out.append(f"  {_fmt_ts(a.ts)}  {a.tool_name:<10} "
                       f"{action_summary(a.tool_name, a.tool_input, limit=100)}")
        out.append("")
    return "\n".join(out)


def render_markdown(records: list, offenses: list, session_id=None,
                    verbose: bool = False, only_agent=None) -> str:
    by_agent = {}
    for o in offenses:
        by_agent.setdefault(o.agent_id, []).append(o)

    if only_agent is not None:
        matches = [r for r in records if _matches(r, only_agent)]
        if not matches:
            return f"no agent matching '{only_agent}' in session {session_id or '(most recent)'}"
        return _render_focus(matches, by_agent, session_id)

    # Drop phantom 0-act agents (SubagentStart/Stop lifecycle records with no tool calls
    # and no offenses) so they don't clutter the report as "? (id) 0 acts" sections.
    shown = [r for r in records if r.actions or by_agent.get(r.agent_id)]
    lines = [f"## Police report — {len(shown)} agents, {len(offenses)} offense(s)", ""]
    for rec in shown:
        offs = by_agent.get(rec.agent_id, [])
        digest = agent_digest(rec, offs)
        lines.append(f"### {agent_label(rec, session_id)}")
        if rec.brief:
            lines.append(f'  assigned: "{rec.brief}"')
        lines.append(f"_{format_digest_line(digest)}_")
        if verbose and digest["files"]:
            lines.append(f"  files: {', '.join(digest['files'])}")
        if offs:
            lines += _offense_table(offs, verbose)
        lines.append("")
    return "\n".join(lines)
