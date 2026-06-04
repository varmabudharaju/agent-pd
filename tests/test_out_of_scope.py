from dataclasses import replace
from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd.detectors import out_of_scope


def _rec(actions, cwd="/proj"):
    return AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd=cwd, actions=actions)


def test_flags_file_outside_project_by_default():
    rules = load_rules(None)  # scope_dirs == [], project_boundary True
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "/etc/passwd"})])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].offense == "out_of_scope"
    assert offs[0].severity == "high"
    assert "outside project" in offs[0].evidence


def test_allows_file_inside_project():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Edit",
                       tool_input={"file_path": "/proj/src/app.py"})])
    assert out_of_scope.detect(rec, rules) == []


def test_sensitive_flagged_even_inside_project():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Read",
                       tool_input={"file_path": "/proj/.env"})])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].severity == "critical"
    assert "sensitive" in offs[0].evidence


def test_allowlist_narrows_within_project():
    rules = replace(load_rules(None), scope_dirs=["src/"])
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "/proj/secrets/key.txt"})])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert "secrets/key.txt" in offs[0].evidence


def test_bash_navigation_outside_project():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "cat /etc/hosts"})])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert "outside project" in offs[0].evidence


def test_bash_inside_project_clean():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "ls src"})])
    assert out_of_scope.detect(rec, rules) == []


def test_dedup_same_path_once():
    rules = load_rules(None)
    rec = _rec([
        Action(agent_id="a1", tool_name="Bash", tool_input={"command": "cat /etc/hosts"}),
        Action(agent_id="a1", tool_name="Bash", tool_input={"command": "cat /etc/hosts"}),
    ])
    assert len(out_of_scope.detect(rec, rules)) == 1


def test_permitted_bash_downgraded_to_info():
    rules = load_rules(None)
    rec = AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/proj",
                      actions=[Action(agent_id="a1", tool_name="Bash",
                                      tool_input={"command": "cat /etc/hosts"})],
                      allow_rules=["Bash(cat:*)"])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].severity == "info"
    assert "permitted" in offs[0].evidence


def test_unpermitted_bash_stays_high():
    rules = load_rules(None)
    rec = AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/proj",
                      actions=[Action(agent_id="a1", tool_name="Bash",
                                      tool_input={"command": "cat /etc/hosts"})],
                      allow_rules=["Bash(ls:*)"])
    assert out_of_scope.detect(rec, rules)[0].severity == "high"


def test_redirect_to_sensitive_stays_critical_not_info():
    # `Bash(git:*)` authorizes RUNNING git, not WRITING the redirect target.
    # The ssh write must remain CRITICAL, not be downgraded to info.
    rules = load_rules(None)
    rec = AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/proj",
                      actions=[Action(agent_id="a1", tool_name="Bash",
                                      tool_input={"command": "git status > ~/.ssh/authorized_keys"})],
                      allow_rules=["Bash(git:*)"])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].severity == "critical"
    assert "permitted" not in offs[0].evidence


def test_sensitive_not_downgraded_by_bare_read_rule():
    # A bare `Read` rule matches everything via is_permitted, but a SENSITIVE
    # path must NEVER be downgraded to info -- it stays critical.
    import os
    rules = load_rules(None)
    rec = AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/proj",
                      actions=[Action(agent_id="a1", tool_name="Read",
                                      tool_input={"file_path": os.path.expanduser("~/.ssh/id_rsa")})],
                      allow_rules=["Read"])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].severity == "critical"
    assert "permitted" not in offs[0].evidence


def test_sensitive_not_downgraded_by_broad_write_glob():
    import os
    rules = load_rules(None)
    rec = AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/proj",
                      actions=[Action(agent_id="a1", tool_name="Write",
                                      tool_input={"file_path": os.path.expanduser("~/.ssh/authorized_keys")})],
                      allow_rules=["Write(~/**)"])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].severity == "critical"
    assert "permitted" not in offs[0].evidence


def test_nonsensitive_boundary_still_downgraded_by_matching_rule():
    # REGRESSION: a NON-sensitive boundary hit with a matching allow-rule must
    # still be downgraded to info.
    import os
    rules = load_rules(None)
    target = os.path.expanduser("~/projects/other/file.py")
    rec = AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/proj",
                      actions=[Action(agent_id="a1", tool_name="Read",
                                      tool_input={"file_path": target})],
                      allow_rules=["Read(~/projects/**)"])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert "outside project" in offs[0].evidence  # confirm boundary, not sensitive
    assert offs[0].severity == "info"
    assert "permitted by allow-rule" in offs[0].evidence


def test_detector_can_be_disabled_via_boundary_and_empty_allowlist():
    rules = replace(load_rules(None), project_boundary=False, scope_dirs=[], sensitive_patterns=[])
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "/etc/passwd"})])
    assert out_of_scope.detect(rec, rules) == []
