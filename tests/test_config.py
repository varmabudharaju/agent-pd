from agent_pd.config import load_rules, Rules

def test_defaults_when_no_file(tmp_path):
    r = load_rules(tmp_path / "missing.yaml")
    assert isinstance(r, Rules)
    # dangerouslyDisableSandbox is now a categorically-dangerous (never-downgrade) regex.
    assert "dangerouslyDisableSandbox" in r.never_downgrade_patterns
    assert any("sudo" in p for p in r.escalation_patterns)
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
    assert r.severity["permitted"] == "info"

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


def test_never_downgrade_patterns_default_present():
    r = load_rules(None)
    assert isinstance(r.never_downgrade_patterns, list)
    assert len(r.never_downgrade_patterns) > 0


def test_pattern_tiers_overridable(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text(
        "escalation_patterns:\n  - my-esc\n"
        "never_downgrade_patterns:\n  - my-nd\n"
    )
    r = load_rules(p)
    assert r.escalation_patterns == ["my-esc"]
    assert r.never_downgrade_patterns == ["my-nd"]


def test_storage_defaults():
    from agent_pd.config import load_rules
    rules = load_rules(None)
    assert rules.storage["retention_days"] is None


def test_storage_override(tmp_path):
    from agent_pd.config import load_rules
    p = tmp_path / "rules.yaml"
    p.write_text("storage:\n  retention_days: 30\n")
    rules = load_rules(p)
    assert rules.storage["retention_days"] == 30


def test_sink_defaults():
    r = load_rules(None)
    assert r.sink["type"] is None
    assert r.sink["url"] is None
    assert r.sink["path"] is None
    assert r.sink["timeout"] == 10


def test_sink_override(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text("sink:\n  type: file\n  path: /x\n")
    r = load_rules(p)
    assert r.sink["type"] == "file"
    assert r.sink["path"] == "/x"
    # unspecified keys keep defaults
    assert r.sink["timeout"] == 10
    assert r.sink["url"] is None


# --- auto-discovery of pd-rules.yaml (no explicit --rules) -----------------------

def test_discover_finds_cwd_file(tmp_path, monkeypatch):
    from agent_pd.config import discover_rules_path
    p = tmp_path / "pd-rules.yaml"
    p.write_text("off_task_overlap_threshold: 0.5\n")
    monkeypatch.chdir(tmp_path)
    assert discover_rules_path(home=tmp_path / "nohome") == p


def test_discover_finds_project_root_from_subdir(tmp_path, monkeypatch):
    from agent_pd.config import discover_rules_path
    (tmp_path / ".git").mkdir()                       # mark tmp_path as a project root
    rules = tmp_path / "pd-rules.yaml"
    rules.write_text("off_task_overlap_threshold: 0.5\n")
    sub = tmp_path / "src" / "deep"
    sub.mkdir(parents=True)
    monkeypatch.chdir(sub)
    assert discover_rules_path(home=tmp_path / "nohome") == tmp_path / "pd-rules.yaml"


def test_discover_finds_home_file(tmp_path, monkeypatch):
    from agent_pd.config import discover_rules_path
    work = tmp_path / "work"                          # a dir with no rules file
    work.mkdir()
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    hp = home / ".claude" / "pd-rules.yaml"
    hp.write_text("off_task_overlap_threshold: 0.5\n")
    monkeypatch.chdir(work)
    assert discover_rules_path(home=home) == hp


def test_discover_returns_none_when_absent(tmp_path, monkeypatch):
    from agent_pd.config import discover_rules_path
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    assert discover_rules_path(home=tmp_path / "nohome") is None


def test_load_rules_auto_uses_discovered_file(tmp_path, monkeypatch):
    from agent_pd.config import load_rules_auto
    (tmp_path / "pd-rules.yaml").write_text("off_task_overlap_threshold: 0.5\n")
    monkeypatch.chdir(tmp_path)
    r = load_rules_auto(home=tmp_path / "nohome")
    assert r.off_task_overlap_threshold == 0.5


def test_load_rules_auto_explicit_beats_discovery(tmp_path, monkeypatch):
    from agent_pd.config import load_rules_auto
    (tmp_path / "pd-rules.yaml").write_text("off_task_overlap_threshold: 0.5\n")
    other = tmp_path / "other.yaml"
    other.write_text("off_task_overlap_threshold: 0.9\n")
    monkeypatch.chdir(tmp_path)
    r = load_rules_auto(str(other), home=tmp_path / "nohome")
    assert r.off_task_overlap_threshold == 0.9


def test_load_rules_auto_defaults_when_none_found(tmp_path, monkeypatch):
    from agent_pd.config import load_rules_auto
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    r = load_rules_auto(home=tmp_path / "nohome")
    assert r.off_task_overlap_threshold == 0.15
