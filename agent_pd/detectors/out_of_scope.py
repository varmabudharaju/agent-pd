import os

from ..models import Offense

OFFENSE = "out_of_scope"
FILE_TOOLS = {"Read", "Write", "Edit", "NotebookEdit"}


def _path_of(tool_input: dict) -> str:
    return tool_input.get("file_path") or tool_input.get("notebook_path") or ""


def _in_scope(path: str, scope_dirs: list, cwd: str) -> bool:
    base = cwd or os.getcwd()
    abspath = path if os.path.isabs(path) else os.path.join(base, path)
    try:
        rel = os.path.relpath(abspath, base)
    except ValueError:
        return False
    rel = rel.replace(os.sep, "/")
    for d in scope_dirs:
        d = d.rstrip("/") + "/"
        if (rel + "/").startswith(d):
            return True
    return False


def detect(record, rules) -> list:
    if not rules.scope_dirs:
        return []
    sev = rules.severity.get(OFFENSE, "high")
    out = []
    for a in record.actions:
        if a.tool_name not in FILE_TOOLS:
            continue
        path = _path_of(a.tool_input)
        if path and not _in_scope(path, rules.scope_dirs, record.cwd):
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                               f"{a.tool_name} touched {path} outside scope "
                               f"{rules.scope_dirs}"))
    return out
