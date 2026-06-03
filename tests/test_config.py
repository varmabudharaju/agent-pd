from agent_pd.config import load_rules, Rules

def test_defaults_when_no_file(tmp_path):
    r = load_rules(tmp_path / "missing.yaml")
    assert isinstance(r, Rules)
    assert "dangerouslyDisableSandbox" in r.escalation_patterns
    assert r.severity["permission_bypass"] == "critical"
    assert r.detectors["off_task"] is True
    assert 0.0 < r.off_task_overlap_threshold < 1.0

def test_user_file_overrides_defaults(tmp_path):
    p = tmp_path / "pd-rules.yaml"
    p.write_text("off_task_overlap_threshold: 0.5\ndetectors:\n  redundant: false\n")
    r = load_rules(p)
    assert r.off_task_overlap_threshold == 0.5
    assert r.detectors["redundant"] is False
    # unspecified keys keep defaults
    assert r.detectors["permission_bypass"] is True
    assert r.severity["off_task"] == "review"

def test_scope_defaults_present():
    r = load_rules(None)
    assert r.project_boundary is True
    assert "~/.ssh" in r.sensitive_patterns
    assert "*.pem" in r.sensitive_patterns
    assert r.severity["out_of_scope"] == "high"
    assert r.severity["out_of_scope_sensitive"] == "critical"

def test_scope_overrides(tmp_path):
    p = tmp_path / "pd-rules.yaml"
    p.write_text("project_boundary: false\nsensitive_patterns:\n  - secret.txt\n")
    r = load_rules(p)
    assert r.project_boundary is False
    assert r.sensitive_patterns == ["secret.txt"]

def test_pdrules_sensitive_matches_defaults():
    import yaml
    from pathlib import Path
    from agent_pd.config import DEFAULT_SENSITIVE
    repo_rules = Path(__file__).resolve().parent.parent / "pd-rules.yaml"
    data = yaml.safe_load(repo_rules.read_text())
    assert data["sensitive_patterns"] == DEFAULT_SENSITIVE
