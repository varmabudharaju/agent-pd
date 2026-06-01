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
