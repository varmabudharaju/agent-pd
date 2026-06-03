from dataclasses import dataclass, field


@dataclass
class Action:
    agent_id: str
    tool_name: str
    tool_input: dict
    ts: str | None = None
    decision: str | None = None       # 'allow' | 'deny' | None
    reason: str | None = None


@dataclass
class AgentRecord:
    agent_id: str
    agent_type: str
    brief: str
    cwd: str
    actions: list = field(default_factory=list)   # list[Action]
    allow_rules: list = field(default_factory=list)   # configured permission allow-rules (for info-downgrade)


@dataclass
class Offense:
    agent_id: str
    agent_type: str
    offense: str
    severity: str
    confidence: str
    evidence: str
    subject: str | None = None   # the thing judged (e.g. an off_task search term)
