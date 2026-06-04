# agent-pd — manual test plan

A hand-runnable verification suite. Each case states a plain-English **intent** (what a
reasonable person expects pd to do), gives **copy-pasteable setup + action**, shows the
**verbatim observed output** captured from the real engine, and a **verdict** (✅ matches
intent / ⚠️ divergence). Every expected output in these files was produced by actually
running `python3 -m agent_pd.cli` — nothing is hand-written.

Run from the repo root with `python3` and an editable install (`pip install --user -e .`).

## The four suites

| File | Area | Cases | Result |
|---|---|---|---|
| [`01-bypass-and-scope.md`](01-bypass-and-scope.md) | `permission_bypass`, `out_of_scope` (escalation tiers, sensitive paths, project boundary, `$VAR`, interpreter one-liners, `scope_dirs`) | 18 | 18/18 ✅ |
| [`02-self-perm-tools-dup-offtask.md`](02-self-perm-tools-dup-offtask.md) | `self_permission`, `tool_not_allowed`, `redundant`, `off_task` | 12 | 11 ✅, 1 by-design note |
| [`03-permission-aware-severity.md`](03-permission-aware-severity.md) | Allow-rule downgrade to `info`; the three never-downgrade guarantees; operator-split, redirect isolation, globs, word-boundary | 10 | 10/10 ✅ |
| [`04-integrity-compact-sink.md`](04-integrity-compact-sink.md) | `pd verify` (tamper / truncation / reorder / insert / HMAC / legacy), `pd compact` losslessness, `pd sink` push/status, hook crash-safety | 16 | 16/16 ✅ |

**Total: 56 cases · 55 match intent · 0 security-critical divergences.** The three
never-downgrade guarantees hold (sensitive paths, catastrophic commands, and denied calls
all stay `critical` even with a matching allow-rule). Every tamper/truncation/reorder/insert
was detected (exit 2); gzip compaction is provably lossless (byte-identical report before/after);
the hook always exits 0 on malformed input.

## Honest findings to know before you publish

None are bugs, but a tester *will* hit these — they're documented in-suite and worth knowing:

1. **`off_task` needs the projects *root*, not the project dir.** The brief is read from
   `<projects-dir>/*/<session_id>/subagents/agent-<id>.meta.json`, so `--projects-dir` must
   point one level **above** the session dir or `off_task` silently never fires. Note:
   `examples/demo.sh` passes the project dir, so `off_task` doesn't fire there by design.
   (Suite 02 builds the correct layout and shows it firing.)
2. **`redundant` ignores the Bash `description`.** Two calls with the same `command` but
   different `description` are flagged duplicate (the detector strips `description` as noise so
   you can't dodge dedup by relabeling). Correct-by-design, but surprising. (Suite 02.)
3. **A catastrophic `/`-targeting command emits two offenses** — a critical never-downgrade
   `permission_bypass` *plus* a separate `out_of_scope` boundary row for the `/` path (which can
   show as `info` if an allow-rule "permits" the bare command). The action stays a crime via the
   critical row; the second row is cosmetic. (Suites 01 & 03.)
4. **`ts` is `null` when events are fed via `write_event` directly** (the harness path); only the
   live hook `main()` stamps arrival time. Cosmetic, affects synthetic logs only. (Suite 04.)
5. **`--rules` is required for `scope_dirs` / custom patterns to take effect**; allow-rules instead
   come from the event cwd's `.claude/settings*.json` (+ `CLAUDE_CONFIG_DIR`). (Suite 01.)

## How the harness works (shared across suites)

Events are fed through the genuine recorder so they are truly hash-chained, then read back by
the real CLI:

```bash
# resolve a non-symlinked base (macOS /tmp -> /private/tmp, else in-project paths look out-of-scope)
SB="$(cd "${TMPDIR:-/tmp}" && pwd -P)/pd-test"; rm -rf "$SB"; mkdir -p "$SB/audit" "$SB/proj"
( cd "$SB/proj" && git init -q )
python3 - "$SB" <<'PY'
from agent_pd import hook
# build_event(payload) -> write_event(event, audit_dir=...) is the real hook code path
PY
python3 -m agent_pd.cli report --session SID --audit-dir "$SB/audit" --projects-dir "$SB/proj" --format md
```

See [`examples/demo.sh`](../../examples/demo.sh) for the canonical working template.
