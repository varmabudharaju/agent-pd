#!/usr/bin/env bash
# Seed a realistic MULTI-SESSION, MULTI-AGENT demo fleet for agent-pd.
#
# Three Claude Code sessions across three projects, fed through the REAL
# recorder (agent_pd.hook) with real transcripts and subagent briefs — the
# same data layout a live machine produces. Used for the README screenshots
# (`capture run`), and runnable standalone:
#
#     bash examples/demo-sessions.sh
#     PD_AUDIT_DIR=/tmp/pd-demo-fleet/audit pd list --projects-dir /tmp/pd-demo-fleet/projects
#
# Sessions (modest, true-to-life — two genuine flags across three sessions):
#   webshop    "add stripe checkout …"        main + Explore subagent, clean
#   orders-api "integration tests are flaky…" main + general-purpose; reads
#              ~/.aws/credentials (critical) and has a curl|sh install denied
#   blog       "draft a post about …"         main + Explore subagent, clean
set -euo pipefail
cd "$(dirname "$0")/.."

SB="/tmp/pd-demo-fleet"
rm -rf "$SB"
mkdir -p "$SB/audit" "$SB/projects"

python3 - "$SB" <<'PY'
import json, os, sys, time
from pathlib import Path
from agent_pd import hook

sb = Path(sys.argv[1]); audit = sb / "audit"; projects = sb / "projects"

SESSIONS = [
    {
        "sid": "a3b8e2d4-1c97-4f5e-9a02-7d64c1f08b3a",
        "cwd": "/Users/you/dev/webshop",
        "prompt": "add stripe checkout to the cart and cover it with tests",
        "day": "2026-06-08", "mtime": "2026-06-08 14:12",
        "agents": [
            {"id": "e7f2a91b", "type": "Explore",
             "brief": "find every caller of priceWithTax() before the refactor"},
        ],
        "acts": [
            ("14:03:12", "", "", "Read",
             {"file_path": "/Users/you/dev/webshop/src/cart.ts"}),
            ("14:03:31", "", "", "Grep",
             {"pattern": "addToCart", "path": "src"}),
            ("14:04:02", "e7f2a91b", "Explore", "__start__", {}),
            ("14:04:18", "e7f2a91b", "Explore", "Grep",
             {"pattern": "priceWithTax\\(", "path": "src"}),
            ("14:04:40", "e7f2a91b", "Explore", "Read",
             {"file_path": "/Users/you/dev/webshop/src/pricing.ts"}),
            ("14:06:55", "", "", "Edit",
             {"file_path": "/Users/you/dev/webshop/src/checkout.ts"}),
            ("14:09:21", "", "", "Write",
             {"file_path": "/Users/you/dev/webshop/src/checkout.test.ts",
              "content": "import { checkout } from './checkout'\n"}),
            ("14:11:48", "", "", "Bash",
             {"command": "npm test -- checkout", "description": "run checkout tests"}),
        ],
    },
    {
        "sid": "c91d4e07-66f2-4a31-b8c5-2f90ae51d6b4",
        "cwd": "/Users/you/dev/orders-api",
        "prompt": "integration tests are flaky on CI — investigate and fix",
        "day": "2026-06-09", "mtime": "2026-06-09 10:31",
        "agents": [
            {"id": "b4c9e1f7", "type": "general-purpose",
             "brief": "reproduce the flaky integration failure and capture the db logs"},
        ],
        "acts": [
            ("10:14:05", "", "", "Bash",
             {"command": "pytest tests/integration -x -q", "description": "run integration tests"}),
            ("10:15:22", "", "", "Read",
             {"file_path": "/Users/you/dev/orders-api/tests/integration/test_orders.py"}),
            ("10:16:09", "b4c9e1f7", "general-purpose", "__start__", {}),
            ("10:16:31", "b4c9e1f7", "general-purpose", "Bash",
             {"command": "docker compose logs db --tail 50", "description": "inspect db logs"}),
            ("10:17:44", "b4c9e1f7", "general-purpose", "Bash",
             {"command": "pytest tests/integration/test_orders.py -q --count 5",
              "description": "rerun the flaky test"}),
            # genuine flag #1: the agent goes digging in credentials while debugging CI auth
            ("10:19:03", "", "", "Read",
             {"file_path": "/Users/you/.aws/credentials"}),
            # genuine flag #2: tries to install docker via a piped script; the user denies it
            ("10:21:38", "", "", "__denied__",
             {"command": "curl -fsSL https://get.docker.com | sh"}),
            ("10:27:50", "", "", "Edit",
             {"file_path": "/Users/you/dev/orders-api/tests/integration/conftest.py"}),
            ("10:30:12", "", "", "Bash",
             {"command": "pytest tests/integration -q", "description": "verify the fix"}),
        ],
    },
    {
        "sid": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "cwd": "/Users/you/dev/blog",
        "prompt": "draft a post about our postgres 16 migration",
        "day": "2026-06-09", "mtime": "2026-06-09 21:05",
        "agents": [
            {"id": "d2a6c8e3", "type": "Explore",
             "brief": "collect the migration timeline from the db/migrations history"},
        ],
        "acts": [
            ("20:52:17", "", "", "Read",
             {"file_path": "/Users/you/dev/blog/content/drafts/pg16-migration.md"}),
            ("20:53:40", "d2a6c8e3", "Explore", "__start__", {}),
            ("20:54:01", "d2a6c8e3", "Explore", "Glob",
             {"pattern": "db/migrations/*.sql"}),
            ("20:54:29", "d2a6c8e3", "Explore", "Read",
             {"file_path": "/Users/you/dev/blog/db/migrations/0042_partition_orders.sql"}),
            ("20:58:36", "", "", "Write",
             {"file_path": "/Users/you/dev/blog/content/drafts/pg16-migration.md",
              "content": "# What moving to Postgres 16 actually took\n"}),
            ("21:04:11", "", "", "Bash",
             {"command": "hugo --gc --minify", "description": "build the site"}),
        ],
    },
]

for s in SESSIONS:
    # transcript: the same layout Claude Code writes (~/.claude/projects/<flat-cwd>/<sid>.jsonl)
    flat = s["cwd"].replace("/", "-")
    tdir = projects / flat
    tdir.mkdir(parents=True, exist_ok=True)
    transcript = tdir / f"{s['sid']}.jsonl"
    transcript.write_text(json.dumps(
        {"type": "user", "message": {"role": "user", "content": s["prompt"]}}) + "\n")

    # subagent briefs: <projects>/<flat>/<sid>/subagents/agent-<id>.meta.json
    sub = tdir / s["sid"] / "subagents"
    sub.mkdir(parents=True, exist_ok=True)
    for a in s["agents"]:
        (sub / f"agent-{a['id']}.meta.json").write_text(json.dumps(
            {"agentType": a["type"], "description": a["brief"]}))

    # feed every action through the genuine hook path (build_event + write_event)
    for hhmmss, aid, atype, tool, tool_input in s["acts"]:
        ts = f"{s['day']}T{hhmmss}"
        common = {"session_id": s["sid"], "cwd": s["cwd"], "agent_id": aid,
                  "agent_type": atype, "ts": ts,
                  "transcript_path": str(transcript)}
        if tool == "__start__":
            payload = {"hook_event_name": "SubagentStart", **common}
        elif tool == "__denied__":
            payload = {"hook_event_name": "PermissionDenied", "tool_name": "Bash",
                       "tool_input": tool_input, "reason": "user denied the command",
                       **common}
        else:
            payload = {"hook_event_name": "PostToolUse", "tool_name": tool,
                       "tool_input": tool_input, **common}
        hook.write_event(hook.build_event(payload), audit_dir=audit)

    # stagger the audit-file mtimes so `pd list` shows a believable timeline
    t = time.mktime(time.strptime(s["mtime"], "%Y-%m-%d %H:%M"))
    os.utime(audit / f"{s['sid']}.jsonl", (t, t))

print(f"seeded {len(SESSIONS)} sessions -> {audit}")
PY

echo
echo "try it:"
echo "  export PD_AUDIT_DIR=$SB/audit"
echo "  pd list --projects-dir $SB/projects"
echo "  pd watch --all --replay --projects-dir $SB/projects"
