"""Live `pd watch` engine: follows the audit log and streams agent activity + crimes.

Split into a pure-logic `LiveMonitor` (state + detector reuse, no styling), a
file-following `tail_events` iterator, and a thin `watch` orchestrator that renders via
`agent_pd.render`. Detectors are reused unchanged by accumulating a per-agent
AgentRecord and emitting each offense once."""
import json
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .models import Action, AgentRecord
from .config import load_rules
from .permissions import load_allow_rules
from .detectors import run_detectors
from .investigator import (
    find_subagents_dir, load_meta, DEFAULT_PROJECTS_DIR, DEFAULT_AUDIT_DIR,
)
from .render import (
    Style, format_banner, format_feed_line, format_rap_sheet, agent_tag, agent_color,
)


@dataclass
class ProcessResult:
    new_agent: bool
    agent_id: str
    agent_type: str
    brief: str
    has_action: bool
    tool_name: str
    tool_input: dict
    ts: object
    new_offenses: list


class LiveMonitor:
    def __init__(self, projects_dir=DEFAULT_PROJECTS_DIR, audit_dir=DEFAULT_AUDIT_DIR):
        self.projects_dir = Path(projects_dir)
        self.audit_dir = Path(audit_dir)
        self.records = {}        # agent_id -> AgentRecord (accumulating)
        self.emitted = {}        # agent_id -> set of (offense, evidence) already shown
        self.tallies = {}        # agent_id -> Counter(severity)
        self.total_acts = 0

    def _load_brief(self, event) -> str:
        aid, sid = event.get("agent_id", ""), event.get("session_id", "")
        if not aid or not sid:
            return ""
        sub = find_subagents_dir(self.projects_dir, sid)
        if sub is None:
            return ""
        _, brief = load_meta(sub / f"agent-{aid}.meta.json")
        return brief

    def process(self, event, rules) -> ProcessResult:
        aid = event.get("agent_id", "")
        atype = event.get("agent_type", "")
        new_agent = False
        if aid not in self.records:
            brief = self._load_brief(event)
            self.records[aid] = AgentRecord(agent_id=aid, agent_type=atype, brief=brief,
                                            cwd=event.get("cwd", ""), actions=[],
                                            allow_rules=load_allow_rules(event.get("cwd", "")))
            self.emitted[aid] = set()
            self.tallies[aid] = Counter()
            new_agent = True
        rec = self.records[aid]
        if atype and not rec.agent_type:
            rec.agent_type = atype

        tool = event.get("tool_name", "")
        if not tool:   # SubagentStart/Stop and other non-tool events
            return ProcessResult(new_agent, aid, rec.agent_type, rec.brief,
                                 False, "", {}, event.get("ts"), [])

        action = Action(agent_id=aid, tool_name=tool,
                        tool_input=event.get("tool_input") or {}, ts=event.get("ts"),
                        decision=event.get("decision"), reason=event.get("reason"))
        rec.actions.append(action)
        self.total_acts += 1

        new = []
        for o in run_detectors(rec, rules):
            key = (o.offense, o.evidence)
            if key not in self.emitted[aid]:
                self.emitted[aid].add(key)
                self.tallies[aid][o.severity] += 1
                new.append(o)
        return ProcessResult(new_agent, aid, rec.agent_type, rec.brief,
                             True, tool, action.tool_input, action.ts, new)

    def rap_sheet(self, style) -> str:
        entries = []
        for aid, rec in self.records.items():
            tools = Counter(a.tool_name for a in rec.actions if a.tool_name)
            entries.append({
                "tag": agent_tag(rec.agent_type, aid),
                "color": agent_color(aid),
                "crimes": dict(self.tallies.get(aid, {})),
                "acts": len(rec.actions),
                "tools": dict(tools),
            })
        return format_rap_sheet(entries, self.total_acts, style)


def _resolve_session_file(audit_dir, session_id):
    audit_dir = Path(audit_dir)
    if session_id:
        return audit_dir / f"{session_id}.jsonl"
    if not audit_dir.exists():
        return None
    files = sorted(audit_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def tail_events(audit_dir, session_id=None, poll_interval=0.5, _max_polls=None):
    """Follow the session audit file, yielding parsed event dicts as lines are appended.
    Tolerant of the file not existing yet and of blank/partial lines. `_max_polls`
    bounds the loop for tests."""
    path = _resolve_session_file(audit_dir, session_id)
    offset, buf, polls = 0, "", 0
    while True:
        if path is None or not Path(path).exists():
            path = _resolve_session_file(audit_dir, session_id)
        else:
            with open(path, "r", encoding="utf-8") as f:
                f.seek(offset)
                buf += f.read()
                offset = f.tell()
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
        polls += 1
        if _max_polls is not None and polls >= _max_polls:
            return
        if poll_interval:
            time.sleep(poll_interval)


def tail_all_events(audit_dir, poll_interval=0.5, _max_polls=None):
    """Follow EVERY session audit file in the dir at once, merging appended events into
    one stream. New session files are picked up automatically. Each event carries its
    own session_id/agent_id, so a single LiveMonitor handles the merged feed."""
    audit_dir = Path(audit_dir)
    offsets, bufs, polls = {}, {}, 0
    while True:
        if audit_dir.exists():
            for path in sorted(audit_dir.glob("*.jsonl")):
                key = str(path)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        f.seek(offsets.get(key, 0))
                        chunk = f.read()
                        offsets[key] = f.tell()
                except OSError:
                    continue
                buf = bufs.get(key, "") + chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            continue
                bufs[key] = buf
        polls += 1
        if _max_polls is not None and polls >= _max_polls:
            return
        if poll_interval:
            time.sleep(poll_interval)


def watch(session=None, crimes_only=False, verbose=False, all_sessions=False, style=None,
          audit_dir=DEFAULT_AUDIT_DIR, projects_dir=DEFAULT_PROJECTS_DIR,
          rules=None, out=print, _events=None) -> int:
    style = style if style is not None else Style()
    rules = rules if rules is not None else load_rules(None)
    mon = LiveMonitor(projects_dir=projects_dir, audit_dir=audit_dir)

    where = "ALL sessions" if all_sessions else f"session {session or '(most recent)'}"
    out(f" agent-pd · watching {where}    [Ctrl-C to stop]")
    out("─" * 80)
    if _events is not None:
        events = _events
    elif all_sessions:
        events = tail_all_events(audit_dir)
    else:
        events = tail_events(audit_dir, session)
    try:
        for ev in events:
            res = mon.process(ev, rules)
            sess = ev.get("session_id") if all_sessions else None
            if res.new_agent:
                out(format_banner(res.agent_type, res.agent_id, res.brief, style, session=sess))
            if res.has_action:
                for ln in format_feed_line(res.ts, res.agent_type, res.agent_id,
                                           res.tool_name, res.tool_input,
                                           res.new_offenses, style, crimes_only, verbose,
                                           session=sess):
                    out(ln)
    except KeyboardInterrupt:
        pass
    out("─" * 80)
    total_crimes = sum(sum(c.values()) for c in mon.tallies.values())
    if crimes_only and total_crimes == 0 and mon.total_acts:
        out(" no crimes — here's what each agent did instead "
            "(drop --crimes-only to see the live action feed):")
    out(mon.rap_sheet(style))
    return 0
