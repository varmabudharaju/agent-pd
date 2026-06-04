from agent_pd import agents_def


def _write_agent(dirpath, name, frontmatter):
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / f"{name}.md").write_text(f"---\n{frontmatter}\n---\nbody\n")


def test_tools_as_list(tmp_path):
    _write_agent(tmp_path / ".claude" / "agents", "Explore", "tools: [Read, Grep]\nmodel: opus")
    assert agents_def.load_agent_tools("Explore", str(tmp_path)) == {"Read", "Grep"}


def test_tools_as_csv_string(tmp_path):
    _write_agent(tmp_path / ".claude" / "agents", "Explore", "tools: Read, Grep, Bash")
    assert agents_def.load_agent_tools("Explore", str(tmp_path)) == {"Read", "Grep", "Bash"}


def test_no_tools_key_returns_none(tmp_path):
    _write_agent(tmp_path / ".claude" / "agents", "Explore", "model: opus")
    assert agents_def.load_agent_tools("Explore", str(tmp_path)) is None


def test_missing_def_returns_none(tmp_path):
    assert agents_def.load_agent_tools("Nope", str(tmp_path), config_dir=str(tmp_path / "cfg")) is None


def test_empty_agent_type_returns_none(tmp_path):
    assert agents_def.load_agent_tools("", str(tmp_path)) is None


def test_agent_type_case_insensitive_match(tmp_path):
    # File is lowercase explore.md; a self-reported "Explore"/"EXPLORE" must still
    # resolve the same allowlist (can't dodge the allowlist by altering casing).
    _write_agent(tmp_path / ".claude" / "agents", "explore", "tools: [Read, Grep]")
    assert agents_def.load_agent_tools("Explore", str(tmp_path)) == {"Read", "Grep"}
    assert agents_def.load_agent_tools("EXPLORE", str(tmp_path)) == {"Read", "Grep"}
    assert agents_def.load_agent_tools("explore", str(tmp_path)) == {"Read", "Grep"}


def test_agent_type_case_insensitive_kebab(tmp_path):
    # Real CC agent files are lowercase-kebab; a "Code-Reviewer" report resolves
    # the code-reviewer.md allowlist.
    _write_agent(tmp_path / ".claude" / "agents", "code-reviewer", "tools: Read")
    assert agents_def.load_agent_tools("Code-Reviewer", str(tmp_path)) == {"Read"}


def test_agent_type_case_insensitive_config_dir(tmp_path):
    # Case-insensitive match also applies to the user config-dir fallback.
    _write_agent(tmp_path / "cfg" / "agents", "explore", "tools: Read")
    assert agents_def.load_agent_tools("Explore", str(tmp_path / "noproj"),
                                       config_dir=str(tmp_path / "cfg")) == {"Read"}
