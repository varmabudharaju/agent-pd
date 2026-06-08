import json
from agent_pd.models import AgentRecord, Offense
from agent_pd.detectors import run_detectors
from agent_pd.config import load_rules
from agent_pd.report import render_json, render_markdown
from agent_pd.models import Action

def test_run_detectors_respects_toggle():
    rules = load_rules(None)
    rules.detectors["off_task"] = False
    rec = AgentRecord(agent_id="a1", agent_type="Explore",
                      brief="auth login", cwd="/x",
                      actions=[Action(agent_id="a1", tool_name="Grep",
                                      tool_input={"pattern": "totally unrelated zebra"})])
    offs = run_detectors(rec, rules)
    assert all(o.offense != "off_task" for o in offs)

def test_render_json_roundtrips():
    offs = [Offense("a1", "Explore", "redundant", "low", "high", "dup Grep")]
    data = json.loads(render_json(offs))
    assert data[0]["offense"] == "redundant"

def test_render_markdown_groups_by_agent():
    recs = [AgentRecord(agent_id="a1", agent_type="Explore", brief="find foo", cwd="/x")]
    offs = [Offense("a1", "Explore", "redundant", "low", "high", "dup Grep")]
    md = render_markdown(recs, offs)
    assert "Explore" in md
    assert "find foo" in md
    assert "redundant" in md
    assert "dup Grep" in md

def test_render_markdown_escapes_pipes():
    recs = [AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/x")]
    offs = [Offense("a1", "Explore", "permission_bypass", "critical", "high",
                    "Bash: cat a | grep b")]
    md = render_markdown(recs, offs)
    assert "a \\| grep b" in md   # pipe escaped so the table isn't broken


def test_main_agent_named_with_project_and_digest():
    recs = [AgentRecord(agent_id="", agent_type="", brief="", cwd="/Users/x/agent-pd",
                        actions=[Action(agent_id="", tool_name="Bash",
                                        tool_input={"command": "ls"}, ts="2026-06-01T11:49:00")])]
    md = render_markdown(recs, [], session_id="339f8c25-aa")
    assert "### main · agent-pd (session 339f8c2)" in md
    assert "1 acts" in md


def test_evidence_truncated_by_default_full_in_verbose():
    long_ev = "Bash: " + "x" * 300
    recs = [AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/x")]
    offs = [Offense("a1", "Explore", "permission_bypass", "critical", "high", long_ev)]
    md = render_markdown(recs, offs)
    assert "…" in md and ("x" * 300) not in md
    md_v = render_markdown(recs, offs, verbose=True)
    assert ("x" * 300) in md_v


def test_verbose_lists_files_touched():
    recs = [AgentRecord(agent_id="", agent_type="", brief="", cwd="/p", actions=[
        Action(agent_id="", tool_name="Read", tool_input={"file_path": "/etc/hosts"})])]
    md = render_markdown(recs, [], verbose=True)
    assert "files: /etc/hosts" in md


def test_agent_focus_lists_actions():
    recs = [AgentRecord(agent_id="a573f36bxyz", agent_type="Explore", brief="find foo", cwd="/x",
                        actions=[Action(agent_id="a573f36bxyz", tool_name="Grep",
                                        tool_input={"pattern": "foo"}, ts="2026-06-01T12:00:00")]),
            AgentRecord(agent_id="b1", agent_type="Plan", brief="", cwd="/x")]
    md = render_markdown(recs, [], session_id="s1", only_agent="a573f36b")
    assert "Explore (a573f36b…)" in md
    assert "Plan" not in md
    assert "### actions" in md
    assert "Grep" in md and "foo" in md


def test_agent_focus_not_found():
    recs = [AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/x")]
    md = render_markdown(recs, [], session_id="s1", only_agent="zzz")
    assert "no agent matching 'zzz'" in md


def test_report_skips_empty_agents():
    # Subagent lifecycle records (SubagentStart/Stop) create a 0-act AgentRecord that
    # should NOT clutter the report as a phantom "? (id) 0 acts" section.
    from agent_pd.models import AgentRecord, Action
    busy = AgentRecord(agent_id="", agent_type="main", brief="", cwd="/p",
                       actions=[Action(agent_id="", tool_name="Bash", tool_input={"command": "ls"})])
    ghost = AgentRecord(agent_id="ghost123", agent_type="", brief="", cwd="", actions=[])
    md = render_markdown([busy, ghost], [], session_id="S")
    assert "ghost123" not in md
    assert "1 agents" in md
