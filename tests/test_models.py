from agent_pd.models import Action, AgentRecord, Offense

def test_action_defaults():
    a = Action(agent_id="a1", tool_name="Bash", tool_input={"command": "ls"})
    assert a.decision is None

def test_agent_record_holds_actions():
    rec = AgentRecord(agent_id="a1", agent_type="Explore", brief="find foo", cwd="/x")
    rec.actions.append(Action(agent_id="a1", tool_name="Grep", tool_input={"pattern": "foo"}))
    assert len(rec.actions) == 1
    assert rec.actions[0].tool_name == "Grep"

def test_agent_record_allow_rules_default():
    rec = AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/x")
    assert rec.allow_rules == []

def test_offense_fields():
    o = Offense(agent_id="a1", agent_type="Explore", offense="redundant",
                severity="low", confidence="high", evidence="dup Grep")
    assert o.offense == "redundant"
