import os

from ..models import Offense
from .. import scope as scopelib

OFFENSE = "out_of_scope"
FILE_TOOLS = {"Read", "Write", "Edit", "NotebookEdit"}


def _file_path(tool_input: dict) -> str:
    return tool_input.get("file_path") or tool_input.get("notebook_path") or ""


def detect(record, rules) -> list:
    root = scopelib.project_root(record.cwd)
    cwd = record.cwd or os.getcwd()
    high = rules.severity.get(OFFENSE, "high")
    crit = rules.severity.get("out_of_scope_sensitive", "critical")
    out, seen = [], set()
    for a in record.actions:
        raw_paths = []
        if a.tool_name in FILE_TOOLS:
            p = _file_path(a.tool_input or {})
            if p:
                raw_paths.append(p)
            tool_label = a.tool_name
        elif a.tool_name == "Bash":
            raw_paths = scopelib.extract_paths(str((a.tool_input or {}).get("command", "")))
            tool_label = "Bash"
        else:
            continue
        for raw in raw_paths:
            abspath = scopelib.resolve(raw, cwd)
            kind, detail = scopelib.classify(abspath, root, rules.scope_dirs,
                                             rules.sensitive_patterns,
                                             project_boundary=rules.project_boundary)
            if kind is None:
                continue
            key = (tool_label, abspath, kind)
            if key in seen:
                continue
            seen.add(key)
            if kind == "sensitive":
                ev = f"{tool_label} touched {raw} (sensitive: {detail})"
                out.append(Offense(record.agent_id, record.agent_type, OFFENSE, crit, "high", ev))
            elif kind == "boundary":
                ev = f"{tool_label} touched {raw} (outside project {detail})"
                out.append(Offense(record.agent_id, record.agent_type, OFFENSE, high, "high", ev))
            else:
                ev = f"{tool_label} touched {raw} (outside scope {detail})"
                out.append(Offense(record.agent_id, record.agent_type, OFFENSE, high, "high", ev))
    return out
