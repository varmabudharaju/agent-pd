from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd.detectors import off_task

RULES = load_rules(None)   # threshold 0.15

def _rec(actions, brief):
    return AgentRecord(agent_id="a1", agent_type="Explore", brief=brief, cwd="/x", actions=actions)

def test_bash_grep_offtask_flagged():
    # agents often search via shell grep, not the Grep tool — off_task must see it.
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": 'grep -r "kubernetes" /home/dev/agent-pd'})],
               brief="find the version string")
    offs = off_task.detect(rec, RULES)
    assert len(offs) == 1 and offs[0].offense == "off_task"

def test_bash_grep_ontask_not_flagged():
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": 'grep -r "version" pyproject.toml'})],
               brief="find the version string")
    assert off_task.detect(rec, RULES) == []

def test_bash_non_search_command_ignored():
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "git commit -m done"})],
               brief="find the version string")
    assert off_task.detect(rec, RULES) == []

def test_bash_grep_extracts_term_not_whole_command():
    # The on-brief grep term must win even when paths/flags would dilute the overlap.
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": 'grep -rn "\\.claude" /home/dev/agent-pd/agent_pd/ --include=*.py'})],
               brief="Find .claude filesystem access")
    assert off_task.detect(rec, RULES) == []   # term ".claude" overlaps brief -> not off-task

def test_off_task_evidence_names_term_and_brief():
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": 'grep -r "kubernetes" .'})],
               brief="find the version string")
    offs = off_task.detect(rec, RULES)
    assert len(offs) == 1
    assert "kubernetes" in offs[0].evidence
    assert "find the version string" in offs[0].evidence

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

def test_extract_search_term_skips_flag_values():
    from agent_pd.detectors.off_task import _extract_search_term
    assert _extract_search_term('rg -t py "foo"') == "foo"
    assert _extract_search_term("grep -e bar baz") == "bar"
    assert _extract_search_term("grep foo .") == "foo"
    assert _extract_search_term("grep -rn foo /path") == "foo"


def test_long_query_evidence_is_full():
    from agent_pd.models import Action, AgentRecord
    from agent_pd.config import load_rules
    from agent_pd.detectors import off_task
    rules = load_rules(None)
    q = "z" * 200
    rec = AgentRecord(agent_id="a1", agent_type="x", brief="fix the parser", cwd="/p",
                      actions=[Action(agent_id="a1", tool_name="Grep", tool_input={"pattern": q})])
    offs = off_task.detect(rec, rules)
    assert len(offs) == 1
    assert q in offs[0].evidence and "…" not in offs[0].evidence
