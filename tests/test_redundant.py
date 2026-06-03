from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd.detectors import redundant

RULES = load_rules(None)

def _rec(actions):
    return AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/x", actions=actions)

def test_flags_exact_duplicate_once():
    a = lambda: Action(agent_id="a1", tool_name="Grep", tool_input={"pattern": "foo"})
    rec = _rec([a(), a(), a()])   # 3 identical -> one offense (on the 2nd)
    offs = redundant.detect(rec, RULES)
    assert len(offs) == 1
    assert offs[0].offense == "redundant"
    assert offs[0].severity == "low"

def test_duplicate_bash_ignores_description_field():
    # Same command, different agent-written description, must still count as a duplicate.
    rec = _rec([
        Action(agent_id="a1", tool_name="Bash",
               tool_input={"command": "grep -r x .", "description": "first run"}),
        Action(agent_id="a1", tool_name="Bash",
               tool_input={"command": "grep -r x .", "description": "second run"}),
    ])
    offs = redundant.detect(rec, RULES)
    assert len(offs) == 1
    assert offs[0].offense == "redundant"

def test_distinct_inputs_no_offense():
    rec = _rec([
        Action(agent_id="a1", tool_name="Grep", tool_input={"pattern": "foo"}),
        Action(agent_id="a1", tool_name="Grep", tool_input={"pattern": "bar"}),
    ])
    assert redundant.detect(rec, RULES) == []


def test_read_rereads_not_flagged():
    from agent_pd.models import Action, AgentRecord
    from agent_pd.config import load_rules
    from agent_pd.detectors import redundant
    rules = load_rules(None)
    rec = AgentRecord(agent_id="a1", agent_type="x", brief="b", cwd="/p", actions=[
        Action(agent_id="a1", tool_name="Read", tool_input={"file_path": "/p/app.py"}),
        Action(agent_id="a1", tool_name="Read", tool_input={"file_path": "/p/app.py"}),
    ])
    assert redundant.detect(rec, rules) == []


def test_bash_duplicates_still_flagged():
    from agent_pd.models import Action, AgentRecord
    from agent_pd.config import load_rules
    from agent_pd.detectors import redundant
    rules = load_rules(None)
    rec = AgentRecord(agent_id="a1", agent_type="x", brief="b", cwd="/p", actions=[
        Action(agent_id="a1", tool_name="Bash", tool_input={"command": "ls"}),
        Action(agent_id="a1", tool_name="Bash", tool_input={"command": "ls"}),
    ])
    assert len(redundant.detect(rec, rules)) == 1
