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
    # --- system credential / identity files -------------------------------------
    # Reading these (e.g. `cat /etc/shadow`) is textbook sensitive: password hashes,
    # account identities, sudo rules, ssh host keys, root's home. Listing them as
    # SENSITIVE (not merely a project-boundary hit) makes them critical and IMMUNE
    # to downgrade -- a broad allow-rule like bare `Bash`/`Read` can never excuse it.
    "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/sudoers", "/etc/sudoers.d",
    "/etc/ssh",            # sshd_config + host keys (dir-prefix)
    "/root",               # root's home (dir-prefix)
    # macOS / BSD variants
    "/etc/master.passwd", "/private/etc/master.passwd", "/private/etc/sudoers",
    # shell history (credential leakage)
    "~/.bash_history", "~/.zsh_history",
]

# Escalation patterns are case-insensitive REGEXes matched (re.search) against the
# Bash command. Two tiers:
#   escalation_patterns      — a PRECISE allow-rule may legitimately downgrade to info.
#   never_downgrade_patterns — categorically dangerous; always critical, never downgraded.
# --- rm recursive-force matching --------------------------------------------------
# Tiering an `rm -rf` depends ENTIRELY on its TARGET, so we match the recursive+force
# flags then a target token. `_RM_RF` matches `rm` carrying BOTH a recursive flag and a
# force flag, in any order, expressed as:
#   recursive: a combined short cluster containing r/R (-rf, -fR, -vrf, ...),
#              a standalone -r/-R, or the long --recursive
#   force:     a combined short cluster containing f, a standalone -f, or the long --force
# Other flags (e.g. --no-preserve-root, -v) may be interleaved. We require, in either
# order, "a force-bearing flag" + "a recursive-bearing flag" (or one combined cluster
# carrying both), consuming any flags around/between them up to the first non-flag arg.
#
# A target token is then matched against the tier-specific patterns below. Targets are
# anchored by an "end of token" lookahead — whitespace, a quote (JSON-escaped \" or a
# literal ' / "), `*`, or end of string — so `/` matches the root token but NOT a
# mid-path slash like /tmp/x. Targets also tolerate ONE optional leading quote so that
# `rm -rf "/"` / `rm -rf '/'` (quoted root) tier identically to the bare form.
# A combined short cluster carrying both r/R and f (e.g. -rf, -fr, -Rf, -vrf).
_RM_BOTH = r"-(?=[a-z]*[rR])(?=[a-z]*f)[a-z]+"
# A recursive-bearing flag: combined cluster with r/R, standalone -r/-R, or --recursive.
_RM_REC = r"(?:-[a-z]*[rR][a-z]*\b|--recursive\b)"
# A force-bearing flag: combined cluster with f, standalone -f, or --force.
_RM_FRC = r"(?:-[a-z]*f[a-z]*\b|--force\b)"
# any run of additional flags (each `-...`) separated by whitespace, possibly empty
_RM_FLAGS = r"(?:-\S+\s+)*"
_RM_RF = (
    r"\brm\s+" + _RM_FLAGS
    + r"(?:"
    + _RM_BOTH + r"\b"                                  # one cluster has both
    + r"|" + _RM_REC + r"\s+" + _RM_FLAGS + _RM_FRC     # recursive then force
    + r"|" + _RM_FRC + r"\s+" + _RM_FLAGS + _RM_REC     # force then recursive
    + r")"
    + r"\s+" + _RM_FLAGS
    + r"""(?:\\?["'])?"""                               # optional leading quote on target
)
# End-of-target-token: whitespace, a quote (\" escaped, or literal ' / "), or end.
_TGT_END = r"""(?=\s|\\?["']|$)"""

DEFAULT_ESCALATION = [
    r"\bsudo\b",
    r"\bdoas\b",
    r"\bchmod\s+(?:-\S+\s+)*[0-7]*7{2,}[0-7]*\b",   # 777-ish (world-writable)
    r"\bchmod\s+[0-7]*[4-7][0-7]{3}\b",             # setuid/setgid/sticky high bit
    r"\bchmod\s+\S*\+s\b",                          # setuid via symbolic mode
    r"\bchown\s+root\b",
    r"\bshred\b",
    # whole-working-directory wipe: `rm -rf .`, `./`, or `*` -- destructive but sometimes
    # a deliberate clean rebuild, so flag it yet let a precise allow-rule excuse it.
    _RM_RF + r"\.\/?" + _TGT_END,
    _RM_RF + r"\*" + _TGT_END,
    # a recursive-force delete rooted in HOME but targeting a subpath (~/projects/x):
    # risky enough to surface, but downgradable by a precise rule (home root is Tier 1).
    _RM_RF + r"~/[^\"\s]",
]

DEFAULT_NEVER_DOWNGRADE = [
    # Catastrophic rm: recursive+force against a SYSTEM or HOME root. Never excusable.
    #   filesystem root: `rm -rf /`, `rm -rf /*`, `rm -rf / --flag`, `rm -rf "/"`
    _RM_RF + r"/" + r"""(?=\s|\\?["']|\*|$)""",
    #   home root: `rm -rf ~`, `rm -rf ~/`, `rm -rf $HOME`, `rm -rf ${HOME}`
    _RM_RF + r"~/?" + _TGT_END,
    _RM_RF + r"\$\{?HOME\}?/?" + _TGT_END,
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
    "sink": {
        "type": None,      # None disabled; "file" | "http"
        "url": None,       # http
        "path": None,      # file
        "timeout": 10,
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
    sink: dict


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
        sink=data["sink"],
    )
