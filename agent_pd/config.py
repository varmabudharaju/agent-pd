from dataclasses import dataclass
from pathlib import Path
import copy
import yaml

DEFAULT_SENSITIVE = [
    "~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.config",
    # ~/.claude holds the pd audit dir, settings, and hooks -- all security-
    # relevant. Flagging it stops an agent from tampering with its own evidence
    # (e.g. `> ~/.claude/pd/audit/<sid>.jsonl`) or reading/editing CC config.
    "~/.claude",
    ".env", ".env.*",
    "*.pem", "*.key", "id_rsa", "id_ed25519", "*.p12",
    ".netrc", ".npmrc", ".pypirc", ".git-credentials",
    "*.keychain",
]

# Escalation patterns are case-insensitive REGEXes matched (re.search) against the
# Bash command. Two tiers:
#   escalation_patterns      — a PRECISE allow-rule may legitimately downgrade to info.
#   never_downgrade_patterns — categorically dangerous; always critical, never downgraded.
DEFAULT_ESCALATION = [
    r"\bsudo\b",
    r"\bdoas\b",
    r"\bchmod\s+(?:-\S+\s+)*[0-7]*7{2,}[0-7]*\b",   # 777-ish (world-writable)
    r"\bchmod\s+[0-7]*[4-7][0-7]{3}\b",             # setuid/setgid/sticky high bit
    r"\bchmod\s+\S*\+s\b",                          # setuid via symbolic mode
    r"\bchown\s+root\b",
    r"\bshred\b",
]

DEFAULT_NEVER_DOWNGRADE = [
    # rm with recursive+force against a dangerous/broad target.
    r"\brm\s+(?:-\S+\s+)*-?[a-z]*r[a-z]*f[a-z]*\b.*(?:/|~|\$HOME|\*)",
    r"\brm\s+(?:-\S+\s+)*-?[a-z]*f[a-z]*r[a-z]*\b.*(?:/|~|\$HOME|\*)",  # -fr order
    r"--no-preserve-root",
    # fork bomb.
    r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}",
    r"\{\s*\w+\s*\|\s*\w+\s*&\s*\}\s*;",            # looser fallback
    # disk destroyers.
    r"\bdd\b.*\bof=/dev/",
    r"\bmkfs(\.\w+)?\b",
    r">\s*/dev/sd",
    # remote-exec pipes.
    r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b",
    # sandbox / permission escapes.
    r"dangerouslyDisableSandbox",
    r"--dangerously-skip-permissions",
]

DEFAULTS = {
    "scope_dirs": [],
    "escalation_patterns": DEFAULT_ESCALATION,
    "never_downgrade_patterns": DEFAULT_NEVER_DOWNGRADE,
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
    never_downgrade_patterns: list
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
        never_downgrade_patterns=data["never_downgrade_patterns"],
        sensitive_patterns=data["sensitive_patterns"],
        project_boundary=data["project_boundary"],
        severity=data["severity"],
        detectors=data["detectors"],
        off_task_overlap_threshold=data["off_task_overlap_threshold"],
        storage=data["storage"],
    )
