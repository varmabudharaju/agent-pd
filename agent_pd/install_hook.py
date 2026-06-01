import json
import sys
from pathlib import Path

HOOK_COMMAND = f"{sys.executable} -m agent_pd.hook"
HOOK_EVENTS = ["PostToolUse", "PermissionDenied", "SubagentStart", "SubagentStop"]


def _entry():
    return {"hooks": [{"type": "command", "command": HOOK_COMMAND}]}


def install_hook(settings_path: Path) -> None:
    settings_path = Path(settings_path)
    cfg = {}
    if settings_path.exists() and settings_path.read_text().strip():
        cfg = json.loads(settings_path.read_text())
    hooks = cfg.setdefault("hooks", {})
    for event in HOOK_EVENTS:
        entries = hooks.setdefault(event, [])
        existing = [h["command"] for e in entries for h in e.get("hooks", [])]
        if HOOK_COMMAND not in existing:
            entries.append(_entry())
    settings_path.write_text(json.dumps(cfg, indent=2) + "\n")
