from dataclasses import dataclass
from pathlib import Path
import copy
import yaml

DEFAULTS = {
    "scope_dirs": [],   # empty = no file-scope restriction
    "escalation_patterns": ["dangerouslyDisableSandbox", "sudo ", "chmod 777", "rm -rf /"],
    "severity": {
        "permission_bypass": "critical",
        "out_of_scope": "high",
        "redundant": "low",
        "off_task": "review",
    },
    "detectors": {
        "permission_bypass": True,
        "out_of_scope": True,
        "redundant": True,
        "off_task": True,
    },
    "off_task_overlap_threshold": 0.15,
}


@dataclass
class Rules:
    scope_dirs: list
    escalation_patterns: list
    severity: dict
    detectors: dict
    off_task_overlap_threshold: float


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_rules(path=None) -> Rules:
    data = copy.deepcopy(DEFAULTS)
    if path is not None and Path(path).exists():
        loaded = yaml.safe_load(Path(path).read_text()) or {}
        data = _deep_merge(data, loaded)
    return Rules(
        scope_dirs=data["scope_dirs"],
        escalation_patterns=data["escalation_patterns"],
        severity=data["severity"],
        detectors=data["detectors"],
        off_task_overlap_threshold=data["off_task_overlap_threshold"],
    )
