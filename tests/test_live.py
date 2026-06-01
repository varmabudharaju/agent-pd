import json
from agent_pd.live import LiveMonitor, tail_events, watch
from agent_pd.config import load_rules
from agent_pd.render import Style

RULES = load_rules(None)


def _ev(agent_id, tool, inp, event="PostToolUse", decision=None, reason=None,
        agent_type="gp", session="s1"):
    return {"event": event, "session_id": session, "agent_id": agent_id,
            "agent_type": agent_type, "tool_name": tool, "tool_input": inp,
            "decision": decision, "reason": reason, "ts": "12:00"}


def _mon(tmp_path):
    return LiveMonitor(projects_dir=tmp_path / "p", audit_dir=tmp_path / "a")


def test_banner_once_per_agent(tmp_path):
    mon = _mon(tmp_path)
    r1 = mon.process(_ev("a1", "Grep", {"pattern": "foo"}), RULES)
    r2 = mon.process(_ev("a1", "Grep", {"pattern": "bar"}), RULES)
    assert r1.new_agent is True
    assert r2.new_agent is False


def test_denial_flagged_as_permission_bypass(tmp_path):
    mon = _mon(tmp_path)
    r = mon.process(_ev("a1", "Bash", {"command": "rm x"}, event="PermissionDenied",
                        decision="deny", reason="blocked"), RULES)
    assert any(o.offense == "permission_bypass" for o in r.new_offenses)


def test_each_offense_emitted_once(tmp_path):
    mon = _mon(tmp_path)
    a = lambda: _ev("a1", "Grep", {"pattern": "dup"})
    mon.process(a(), RULES)            # 1st: clean
    r2 = mon.process(a(), RULES)       # 2nd: redundant fires
    r3 = mon.process(a(), RULES)       # 3rd: nothing new
    assert any(o.offense == "redundant" for o in r2.new_offenses)
    assert r3.new_offenses == []


def test_tallies_and_total_acts(tmp_path):
    mon = _mon(tmp_path)
    mon.process(_ev("a1", "Bash", {"command": "sudo rm"}), RULES)   # critical
    mon.process(_ev("a1", "Grep", {"pattern": "x"}), RULES)         # clean
    assert mon.total_acts == 2
    assert mon.tallies["a1"]["critical"] == 1


def test_subagent_start_registers_without_action(tmp_path):
    mon = _mon(tmp_path)
    r = mon.process({"event": "SubagentStart", "session_id": "s1", "agent_id": "a1",
                     "agent_type": "Explore", "tool_name": "", "tool_input": {}}, RULES)
    assert r.new_agent is True
    assert r.has_action is False
    assert mon.total_acts == 0


def test_tail_events_reads_appended_lines_tolerates_junk(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "s1.jsonl").write_text(
        json.dumps({"event": "PostToolUse", "agent_id": "a1"}) + "\n"
        + "\n"                                                       # blank line tolerated
        + json.dumps({"event": "PostToolUse", "agent_id": "a2"}) + "\n"
        + '{"partial": ')                                            # partial: not yielded
    evs = list(tail_events(audit, session_id="s1", poll_interval=0, _max_polls=1))
    assert [e["agent_id"] for e in evs] == ["a1", "a2"]


def test_watch_emits_banner_crime_and_rap_sheet(tmp_path):
    out_lines = []
    rc = watch(style=Style(color=False, emoji=False),
               projects_dir=tmp_path / "p", audit_dir=tmp_path / "a", rules=RULES,
               out=out_lines.append, _events=iter([_ev("a1", "Bash", {"command": "sudo rm"})]))
    assert rc == 0
    blob = "\n".join(out_lines)
    assert "a1" in blob and "CRITICAL" in blob and "RAP SHEET" in blob
