from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd.detectors import off_task

RULES = load_rules(None)   # threshold 0.15

def _rec(actions, brief):
    return AgentRecord(agent_id="a1", agent_type="Explore", brief=brief, cwd="/x", actions=actions)

def test_webfetch_uses_prompt_not_url():
    # On-task WebFetch: the URL path is opaque, but the fetch prompt overlaps the brief.
    rec = _rec([Action(agent_id="a1", tool_name="WebFetch",
                       tool_input={"url": "https://example.com/x/y/z.md",
                                   "prompt": "authentication login module details"})],
               brief="refactor the authentication login module")
    assert off_task.detect(rec, RULES) == []

def test_flags_unrelated_search():
    rec = _rec([Action(agent_id="a1", tool_name="Grep",
                       tool_input={"pattern": "billing invoice tax"})],
               brief="refactor the authentication login module")
    offs = off_task.detect(rec, RULES)
    assert len(offs) == 1
    assert offs[0].offense == "off_task"
    assert offs[0].confidence == "low"
    assert offs[0].severity == "review"

def test_related_search_no_offense():
    rec = _rec([Action(agent_id="a1", tool_name="Grep",
                       tool_input={"pattern": "authentication login token"})],
               brief="refactor the authentication login module")
    assert off_task.detect(rec, RULES) == []

def test_non_search_tool_ignored():
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "echo hello world"})],
               brief="refactor the authentication login module")
    assert off_task.detect(rec, RULES) == []

def test_empty_brief_skips():
    rec = _rec([Action(agent_id="a1", tool_name="Grep", tool_input={"pattern": "anything"})],
               brief="")
    assert off_task.detect(rec, RULES) == []
