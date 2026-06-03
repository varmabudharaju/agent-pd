import json
import os
from agent_pd import permissions


def test_is_permitted_bash_prefix():
    rules = ["Bash(cat:*)"]
    assert permissions.is_permitted("Bash", {"command": "cat /etc/hosts"}, "/etc/hosts", rules)
    assert not permissions.is_permitted("Bash", {"command": "vim /etc/hosts"}, "/etc/hosts", rules)


def test_is_permitted_bash_exact():
    assert permissions.is_permitted("Bash", {"command": "env"}, None, ["Bash(env)"])
    assert not permissions.is_permitted("Bash", {"command": "env X=1"}, None, ["Bash(env)"])


def test_is_permitted_file_glob():
    p = os.path.expanduser("~/.config/gh/hosts.yml")
    assert permissions.is_permitted("Read", {"file_path": p}, p, ["Read(~/.config/**)"])
    assert not permissions.is_permitted("Read", {"file_path": "/etc/x"}, "/etc/x", ["Read(~/.config/**)"])


def test_is_permitted_whole_tool():
    assert permissions.is_permitted("Read", {"file_path": "/x"}, "/x", ["Read"])


def test_is_permitted_no_match_tool():
    assert not permissions.is_permitted("Bash", {"command": "cat x"}, "x", ["Read(/x/**)"])


def test_load_allow_rules_merges_user_and_project(tmp_path):
    cfg = tmp_path / "cfg"; cfg.mkdir()
    (cfg / "settings.json").write_text(json.dumps({"permissions": {"allow": ["Bash(ls:*)"]}}))
    proj = tmp_path / "proj"; (proj / ".claude").mkdir(parents=True)
    (proj / ".claude" / "settings.local.json").write_text(
        json.dumps({"permissions": {"allow": ["Read(/x/**)"]}}))
    rules = permissions.load_allow_rules(str(proj), config_dir=str(cfg))
    assert "Bash(ls:*)" in rules
    assert "Read(/x/**)" in rules


def test_load_allow_rules_tolerates_missing(tmp_path):
    assert permissions.load_allow_rules(str(tmp_path), config_dir=str(tmp_path / "nope")) == []
