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
