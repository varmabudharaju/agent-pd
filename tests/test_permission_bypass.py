from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd.detectors import permission_bypass

RULES = load_rules(None)

def _rec(actions):
    return AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/x", actions=actions)

def test_flags_denied_action():
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "rm x"}, decision="deny",
                       reason="blocked", source="audit")])
    offs = permission_bypass.detect(rec, RULES)
    assert len(offs) == 1
    assert offs[0].offense == "permission_bypass"
    assert offs[0].severity == "critical"
    assert "denied" in offs[0].evidence

def test_flags_escalation_pattern_in_input():
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "sudo cat /etc/shadow"})])
    offs = permission_bypass.detect(rec, RULES)
    assert len(offs) == 1
    assert "sudo" in offs[0].evidence

def test_clean_action_no_offense():
    rec = _rec([Action(agent_id="a1", tool_name="Grep", tool_input={"pattern": "foo"})])
    assert permission_bypass.detect(rec, RULES) == []
