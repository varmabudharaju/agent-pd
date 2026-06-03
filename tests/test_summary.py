from collections import Counter
from agent_pd.models import Action, AgentRecord, Offense
from agent_pd import summary


def test_label_main_with_project_and_session():
    rec = AgentRecord(agent_id="", agent_type="", brief="", cwd="/Users/x/agent-pd")
    assert summary.agent_label(rec, "339f8c25-aaaa") == "main · agent-pd (session 339f8c2)"


def test_label_main_without_cwd_or_session():
    rec = AgentRecord(agent_id="", agent_type="", brief="", cwd="")
    assert summary.agent_label(rec, None) == "main"


def test_label_subagent():
    rec = AgentRecord(agent_id="a573f36bxyz", agent_type="Explore", brief="b", cwd="/x")
    assert summary.agent_label(rec, "s1") == "Explore (a573f36b…)"


def test_digest_counts_tools_files_times_crimes():
    rec = AgentRecord(agent_id="", agent_type="", brief="", cwd="/p", actions=[
        Action(agent_id="", tool_name="Bash", tool_input={"command": "ls"}, ts="2026-06-01T11:49:16"),
        Action(agent_id="", tool_name="Read", tool_input={"file_path": "/p/a.py"}, ts="2026-06-01T17:30:55"),
        Action(agent_id="", tool_name="Read", tool_input={"file_path": "/p/a.py"}, ts="2026-06-01T17:31:00"),
    ])
    offs = [Offense("", "", "out_of_scope", "high", "high", "x"),
            Offense("", "", "redundant", "low", "high", "y")]
    d = summary.agent_digest(rec, offs)
    assert d["acts"] == 3
    assert d["first"] == "11:49" and d["last"] == "17:31"
    assert d["tools"] == Counter({"Read": 2, "Bash": 1})
    assert d["files"] == ["/p/a.py"]
    assert d["crimes"] == Counter({"high": 1, "low": 1})


def test_format_digest_line_with_crimes():
    d = {"acts": 53, "first": "11:49", "last": "17:30",
         "tools": Counter({"Bash": 24, "Edit": 12, "Read": 9, "Write": 5}),
         "files": [], "crimes": Counter({"critical": 1, "high": 6})}
    line = summary.format_digest_line(d, emoji=False)
    assert line.startswith("53 acts · 11:49–17:30 · ")
    assert "Bash×24 Edit×12 Read×9" in line
    assert "1 critical" in line and "6 high" in line


def test_format_digest_line_clean_and_no_times():
    d = {"acts": 2, "first": None, "last": None,
         "tools": Counter({"Read": 2}), "files": [], "crimes": Counter()}
    line = summary.format_digest_line(d, emoji=False)
    assert line == "2 acts · Read×2 · clean"
