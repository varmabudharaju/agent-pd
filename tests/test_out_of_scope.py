from dataclasses import replace
from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd.detectors import out_of_scope

def _rec(actions, cwd="/proj"):
    return AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd=cwd, actions=actions)

def test_disabled_when_no_scope_dirs():
    rules = load_rules(None)  # scope_dirs == []
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "/etc/passwd"})])
    assert out_of_scope.detect(rec, rules) == []

def test_flags_path_outside_scope():
    rules = replace(load_rules(None), scope_dirs=["src/"])
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "/proj/secrets/key.txt"})])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].offense == "out_of_scope"
    assert "secrets/key.txt" in offs[0].evidence

def test_allows_path_inside_scope():
    rules = replace(load_rules(None), scope_dirs=["src/"])
    rec = _rec([Action(agent_id="a1", tool_name="Edit",
                       tool_input={"file_path": "/proj/src/app.py"})])
    assert out_of_scope.detect(rec, rules) == []
