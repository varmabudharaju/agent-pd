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
