import os

from ..models import Offense
from .. import scope as scopelib
from ..permissions import is_permitted

OFFENSE = "out_of_scope"
FILE_TOOLS = {"Read", "Write", "Edit", "NotebookEdit"}


def _file_path(tool_input: dict) -> str:
    return tool_input.get("file_path") or tool_input.get("notebook_path") or ""


def detect(record, rules) -> list:
    root = scopelib.project_root(record.cwd)
    cwd = record.cwd or os.getcwd()
    high = rules.severity.get(OFFENSE, "high")
    crit = rules.severity.get("out_of_scope_sensitive", "critical")
    info = rules.severity.get("permitted", "info")
    allow = getattr(record, "allow_rules", []) or []
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
                sev = crit
            elif kind == "boundary":
                ev = f"{tool_label} touched {raw} (outside project {detail})"
                sev = high
            else:
                ev = f"{tool_label} touched {raw} (outside scope {detail})"
                sev = high
            # Authorization can excuse a project-boundary or scope offense, but never a
            # sensitive-path one: a SENSITIVE hit stays critical no matter how broad the
            # allow-rule (a watchdog must not be silenced about ~/.ssh, .env, *.pem, ...).
            if kind != "sensitive" and is_permitted(tool_label, a.tool_input, abspath, allow,
                                                    cwd=cwd, project_root=root):
                sev = info
                ev += " (permitted by allow-rule)"
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high", ev))
    return out
