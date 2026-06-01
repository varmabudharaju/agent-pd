import json
from pathlib import Path
from agent_pd.install_hook import install_hook, HOOK_COMMAND

def test_install_hook_into_empty_settings(tmp_path):
    s = tmp_path / "settings.json"
    s.write_text("{}")
    install_hook(s)
    cfg = json.loads(s.read_text())
    events = cfg["hooks"]
    assert "PostToolUse" in events and "PermissionDenied" in events
    cmds = [h["command"] for entry in events["PostToolUse"] for h in entry["hooks"]]
    assert HOOK_COMMAND in cmds

def test_install_hook_is_idempotent(tmp_path):
    s = tmp_path / "settings.json"
    s.write_text("{}")
    install_hook(s)
    install_hook(s)
    cfg = json.loads(s.read_text())
    cmds = [h["command"] for entry in cfg["hooks"]["PostToolUse"] for h in entry["hooks"]]
    assert cmds.count(HOOK_COMMAND) == 1

def test_install_hook_preserves_existing(tmp_path):
    s = tmp_path / "settings.json"
    s.write_text(json.dumps({"model": "opus", "hooks": {"Stop": [{"hooks": [
        {"type": "command", "command": "other.sh"}]}]}}))
    install_hook(s)
    cfg = json.loads(s.read_text())
    assert cfg["model"] == "opus"
    assert "Stop" in cfg["hooks"]
    assert "PostToolUse" in cfg["hooks"]
