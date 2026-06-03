from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd.detectors import tool_scope


def _rec(actions, allowlist):
    return AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/p",
                       actions=actions, tool_allowlist=allowlist)


def test_tool_outside_allowlist_flagged():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash", tool_input={"command": "ls"})],
               allowlist={"Read", "Grep"})
    offs = tool_scope.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].offense == "tool_not_allowed"
    assert offs[0].severity == "high"
    assert "Bash" in offs[0].evidence


def test_tool_inside_allowlist_clean():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Read", tool_input={"file_path": "/p/x"})],
               allowlist={"Read", "Grep"})
    assert tool_scope.detect(rec, rules) == []


def test_no_allowlist_never_flagged():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash", tool_input={"command": "ls"})],
               allowlist=None)
    assert tool_scope.detect(rec, rules) == []


def test_same_disallowed_tool_flagged_once():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash", tool_input={"command": "ls"}),
                Action(agent_id="a1", tool_name="Bash", tool_input={"command": "pwd"})],
               allowlist={"Read"})
    assert len(tool_scope.detect(rec, rules)) == 1
