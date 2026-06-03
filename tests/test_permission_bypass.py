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

def test_write_content_mentioning_pattern_not_flagged():
    # Writing a file whose CONTENT mentions an escalation word is not a bypass.
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "x.py",
                                   "content": "run sudo later; dangerouslyDisableSandbox"})])
    assert permission_bypass.detect(rec, RULES) == []

def test_bash_dangerous_sandbox_flag_flagged():
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "ls", "dangerouslyDisableSandbox": True})])
    offs = permission_bypass.detect(rec, RULES)
    assert len(offs) == 1
    assert "dangerouslyDisableSandbox" in offs[0].evidence

def test_denied_write_still_flagged():
    # A denied call is a bypass attempt regardless of tool type.
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "x"}, decision="deny", reason="blocked")])
    offs = permission_bypass.detect(rec, RULES)
    assert len(offs) == 1
    assert "denied" in offs[0].evidence

def test_description_mentioning_sudo_is_not_flagged():
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "ls -la", "description": "use sudo to inspect"})])
    assert permission_bypass.detect(rec, RULES) == []

def test_real_sudo_command_is_flagged():
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "sudo rm -rf /tmp/x"})])
    offs = permission_bypass.detect(rec, RULES)
    assert len(offs) == 1
    assert offs[0].severity == "critical"
