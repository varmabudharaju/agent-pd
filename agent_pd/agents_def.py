"""Loads a subagent's declared `tools:` allowlist from its agent definition file
(`.claude/agents/<type>.md` frontmatter). Returns a set of tool names, or None when there
is no definition or no `tools:` key (= unrestricted). Used by the tool_scope detector."""
import os
from pathlib import Path

import yaml


def _parse_tools(front: dict):
    tools = front.get("tools")
    if tools is None:
        return None
    if isinstance(tools, str):
        return {t.strip() for t in tools.split(",") if t.strip()}
    if isinstance(tools, list):
        return {str(t).strip() for t in tools if str(t).strip()}
    return None


def _frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    try:
        data = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _load_one(path: Path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return None
    return _parse_tools(_frontmatter(text))


def load_agent_tools(agent_type: str, cwd: str = "", config_dir: str = None):
    """Project `.claude/agents/<type>.md` takes precedence over the user config dir.
    Returns a set of allowed tool names, or None (no def / no `tools:` key)."""
    if not agent_type:
        return None
    bases = []
    if cwd:
        bases.append(Path(cwd) / ".claude" / "agents")
    cfg = config_dir or os.environ.get("CLAUDE_CONFIG_DIR") or str(Path.home() / ".claude")
    bases.append(Path(cfg) / "agents")
    for base in bases:
        tools = _load_one(base / f"{agent_type}.md")
        if tools is not None:
            return tools
    return None
