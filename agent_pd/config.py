from dataclasses import dataclass
from pathlib import Path
import copy
import yaml

DEFAULT_SENSITIVE = [
    "~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.config",
    ".env", ".env.*",
    "*.pem", "*.key", "id_rsa", "id_ed25519", "*.p12",
    ".netrc", ".npmrc", ".pypirc", ".git-credentials",
    "*.keychain",
]

DEFAULTS = {
    "scope_dirs": [],
    "escalation_patterns": ["dangerouslyDisableSandbox", "sudo ", "chmod 777", "rm -rf /"],
    "sensitive_patterns": DEFAULT_SENSITIVE,
    "project_boundary": True,
    "severity": {
        "permission_bypass": "critical",
        "out_of_scope": "high",
        "out_of_scope_sensitive": "critical",
        "permitted": "info",
        "redundant": "low",
        "off_task": "review",
        "self_permission": "critical",
        "tool_not_allowed": "high",
    },
    "detectors": {
        "permission_bypass": True,
        "out_of_scope": True,
        "redundant": True,
        "off_task": True,
        "self_permission": True,
        "tool_not_allowed": True,
    },
    "off_task_overlap_threshold": 0.15,
    "storage": {
        "retention_days": None,
    },
}


@dataclass
class Rules:
    scope_dirs: list
    escalation_patterns: list
    sensitive_patterns: list
    project_boundary: bool
    severity: dict
    detectors: dict
    off_task_overlap_threshold: float
    storage: dict


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
        sensitive_patterns=data["sensitive_patterns"],
        project_boundary=data["project_boundary"],
        severity=data["severity"],
        detectors=data["detectors"],
        off_task_overlap_threshold=data["off_task_overlap_threshold"],
        storage=data["storage"],
    )
