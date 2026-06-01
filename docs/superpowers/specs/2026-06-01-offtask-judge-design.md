# off_task LLM judge — `pd judge`

**Date:** 2026-06-01
**Status:** Design approved (opt-in, cost-capped)

## Goal
Turn the noisy, low-confidence `off_task` heuristic flags into a small set of
high-confidence verdicts by having an LLM read the agent's brief and each flagged
search and reason about relevance — *only when the user explicitly asks*, and only over
the pre-filtered flagged items.

## Cost guardrails (the whole point)
- **Opt-in.** Never runs in the hook or `pd watch`. Only `pd judge`.
- **Pre-filtered.** Only `off_task`-flagged items are sent — never clean actions, never
  the deterministic crimes.
- **Batched per agent.** One API call per agent (brief + all its flagged searches),
  not per search.
- **Cheap model by default.** `--model haiku` (default), `sonnet`, or `opus`.
- **Dry-run by default.** `pd judge` prints an estimate (items, agents, ≈tokens) and
  does nothing else. `--run` actually calls the API. `--max N` caps items.
- **Graceful no-op** when `anthropic` isn't installed or no API key is set.

## Architecture
- `anthropic` is an **optional** dependency (`pip install -e ".[judge]"`); imported
  lazily inside `judge.py`. Core stays zero-dependency.
- `agent_pd/models.py`: `Offense` gains an optional `subject` field (the thing judged —
  the search term), so the judge has a clean handle instead of parsing evidence.
- `agent_pd/judge.py`:
  - `MODEL_ALIASES = {haiku→claude-haiku-4-5, sonnet→claude-sonnet-4-6, opus→claude-opus-4-8}`.
  - `estimate(records, rules)` → `{items, agents, calls, approx_input_tokens, approx_output_tokens}`.
  - `build_prompt(brief, subjects)` → `(system_rubric, user_text)`.
  - `judge_records(records, rules, model, client, max_items)` → `{confirmed, dropped, usage}`.
    For each agent with `off_task` offenses: one structured-output call returns a verdict
    per search; confirmed off-task items become **high-confidence** Offenses (evidence =
    the judge's reason), false positives are dropped.
  - API call isolated in `_call_model(client, model_id, system, user)` using
    `output_config.format` (JSON schema). Client is injectable for tests.
- `agent_pd/cli.py`: `pd judge` subcommand (dry-run default, `--run`, `--model`, `--max`).

## Out of scope
- Judging anything but `off_task` (the deterministic detectors are already trustworthy).
- Verdict disk cache (a fast-follow; estimate already keeps cost visible).
