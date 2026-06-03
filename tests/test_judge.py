import json
from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd import judge

RULES = load_rules(None)


def _rec(brief, commands):
    actions = [Action(agent_id="a1", tool_name="Bash", tool_input={"command": c})
               for c in commands]
    return AgentRecord(agent_id="a1", agent_type="Explore", brief=brief, cwd="/x",
                       actions=actions)


class _FakeMessages:
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        text = json.dumps(self.payload)
        block = type("B", (), {"type": "text", "text": text})()
        usage = type("U", (), {"input_tokens": 10, "output_tokens": 5})()
        return type("R", (), {"content": [block], "usage": usage})()


class _FakeClient:
    def __init__(self, payload):
        self.messages = _FakeMessages(payload)


def test_build_prompt_numbers_subjects_and_includes_brief():
    system, user = judge.build_prompt("find the version", ["kubernetes", "tensorflow"])
    assert "find the version" in user
    assert "0. kubernetes" in user and "1. tensorflow" in user
    assert "off-task" in system.lower()


def test_estimate_counts_items_and_agents():
    rec = _rec("find the version string",
               ['grep -r "kubernetes" .', 'grep -r "tensorflow" .'])
    est = judge.estimate([rec], RULES)
    assert est["items"] == 2
    assert est["agents"] == 1 and est["calls"] == 1
    assert est["approx_input_tokens"] > 0


def test_judge_confirms_true_and_drops_false_positive():
    rec = _rec("find the version string",
               ['grep -r "kubernetes" .', 'grep -r "tensorflow" .'])  # both flagged off_task
    client = _FakeClient({"verdicts": [
        {"index": 0, "off_task": True, "reason": "unrelated to version"},
        {"index": 1, "off_task": False, "reason": "plausibly related"},
    ]})
    result = judge.judge_records([rec], RULES, client=client)
    assert len(result["confirmed"]) == 1
    assert result["confirmed"][0].subject == "kubernetes"
    assert result["confirmed"][0].confidence == "high"      # heuristic -> verdict
    assert "judged off-task" in result["confirmed"][0].evidence
    assert result["dropped"] == 1
    assert result["usage"]["input_tokens"] == 10


def test_judge_respects_max_items():
    rec = _rec("find the version string",
               ['grep -r "kubernetes" .', 'grep -r "tensorflow" .', 'grep -r "redis" .'])
    client = _FakeClient({"verdicts": [{"index": 0, "off_task": True, "reason": "x"}]})
    result = judge.judge_records([rec], RULES, client=client, max_items=1)
    # only 1 item sent -> at most 1 confirmed, and exactly one API call
    assert len(result["confirmed"]) <= 1
    assert client.messages.calls == 1


def test_model_alias_resolves():
    assert judge.MODEL_ALIASES["haiku"] == "claude-haiku-4-5"
    assert judge.MODEL_ALIASES["opus"] == "claude-opus-4-8"


def test_extract_verdicts_from_prose_and_fences():
    fenced = 'Here you go:\n```json\n{"verdicts": [{"index": 0, "off_task": true, "reason": "x"}]}\n```\ndone'
    obj = judge._extract_verdicts(fenced)
    assert obj["verdicts"][0]["off_task"] is True
    assert judge._extract_verdicts("no json here") == {"verdicts": []}


def test_judge_tolerates_id_key_from_free_form_json():
    # the claude-CLI path returns free-form JSON that may use "id" instead of "index"
    rec = _rec("find the version string", ['grep -r "kubernetes" .'])
    client = _FakeClient({"verdicts": [{"id": 0, "off_task": True, "reason": "unrelated"}]})
    result = judge.judge_records([rec], RULES, client=client)
    assert len(result["confirmed"]) == 1


def test_judge_via_injected_call_backend():
    # backend path uses an injected `call` (mirrors the claude-code subprocess shape)
    rec = _rec("find the version string",
               ['grep -r "kubernetes" .', 'grep -r "tensorflow" .'])
    calls = {"n": 0}

    def fake_call(system, user):
        calls["n"] += 1
        return {"verdicts": [
            {"index": 0, "off_task": True, "reason": "unrelated"},
            {"index": 1, "off_task": False, "reason": "related"},
        ]}, None

    result = judge.judge_records([rec], RULES, call=fake_call)
    assert calls["n"] == 1
    assert len(result["confirmed"]) == 1 and result["dropped"] == 1


def test_judge_isolates_backend_errors():
    from agent_pd.models import Action, AgentRecord
    from agent_pd.config import load_rules
    from agent_pd import judge as judge_mod
    rules = load_rules(None)
    recs = [
        AgentRecord(agent_id="a1", agent_type="x", brief="fix the parser", cwd="/p",
                    actions=[Action(agent_id="a1", tool_name="Grep", tool_input={"pattern": "kubernetes"})]),
        AgentRecord(agent_id="a2", agent_type="x", brief="fix the parser", cwd="/p",
                    actions=[Action(agent_id="a2", tool_name="Grep", tool_input={"pattern": "billing"})]),
    ]
    calls = {"n": 0}
    def flaky_call(system, user):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("backend boom")
        return {"verdicts": [{"index": 0, "off_task": True, "reason": "unrelated"}]}, None
    result = judge_mod.judge_records(recs, rules, call=flaky_call)
    assert result["errored"] == 1
    assert len(result["confirmed"]) == 1
    assert "errored" in result
