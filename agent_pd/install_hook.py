import json
import os
import shlex
import sys
from pathlib import Path

HOOK_COMMAND = f"{sys.executable} -m agent_pd.hook"
HOOK_EVENTS = ["PostToolUse", "PermissionDenied", "SubagentStart", "SubagentStop"]


def hook_command(audit_dir=None) -> str:
    """The command registered in settings.json. With audit_dir, bake `--audit-dir
    PATH` in so the hook writes there regardless of the user's shell environment."""
    cmd = HOOK_COMMAND
    if audit_dir:
        # Bake an ABSOLUTE path (abspath, not resolve — no symlink rewriting) so the hook
        # never writes to a dir relative to Claude's changing cwd.
        abs = os.path.abspath(os.path.expanduser(str(audit_dir)))
        cmd += " --audit-dir " + shlex.quote(abs)
    return cmd


def install_hook(settings_path: Path, audit_dir=None) -> None:
    settings_path = Path(settings_path)
    command = hook_command(audit_dir)
    cfg = {}
    if settings_path.exists() and settings_path.read_text().strip():
        cfg = json.loads(settings_path.read_text())
    hooks = cfg.setdefault("hooks", {})
    for event in HOOK_EVENTS:
        entries = hooks.setdefault(event, [])
        existing = [h["command"] for e in entries for h in e.get("hooks", [])]
        if command not in existing:
            entries.append({"hooks": [{"type": "command", "command": command}]})
    settings_path.write_text(json.dumps(cfg, indent=2) + "\n")
