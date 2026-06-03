# Richer pd report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `pd report` clearer — a named main agent, a per-agent activity digest, and drill-down via `--verbose`, `--agent <id>`, and a files-touched list.

**Architecture:** New pure `agent_pd/summary.py` (label + digest). `report.render_markdown` gains the digest line + focus mode and moves evidence truncation to the render layer (detectors emit full evidence). CLI threads the resolved session id + two flags. Presentation-only; no detector logic changes.

**Tech Stack:** Python 3.11 stdlib (`os`, `collections.Counter`), pytest. No new deps.

---

## File structure

| File | Responsibility | Action |
|---|---|---|
| `agent_pd/summary.py` | `agent_label`, `agent_digest`, `format_digest_line` (pure) | **create** |
| `agent_pd/report.py` | markdown layout: header+digest+table+focus; render-layer truncation | rewrite |
| `agent_pd/cli.py` | resolve session id; `-v/--verbose` + `--agent` flags | modify |
| `agent_pd/detectors/permission_bypass.py` `redundant.py` `off_task.py` | emit FULL evidence (drop truncation) | modify |

---

## Task 1: `summary.py` — label + digest helpers

**Files:** Create `agent_pd/summary.py`; Test `tests/test_summary.py`.

- [ ] **Step 1: Write the failing test** — create `tests/test_summary.py`:

```python
from collections import Counter
from agent_pd.models import Action, AgentRecord, Offense
from agent_pd import summary


def test_label_main_with_project_and_session():
    rec = AgentRecord(agent_id="", agent_type="", brief="", cwd="/Users/x/agent-pd")
    assert summary.agent_label(rec, "339f8c25-aaaa") == "main · agent-pd (session 339f8c2)"


def test_label_main_without_cwd_or_session():
    rec = AgentRecord(agent_id="", agent_type="", brief="", cwd="")
    assert summary.agent_label(rec, None) == "main"


def test_label_subagent():
    rec = AgentRecord(agent_id="a573f36bxyz", agent_type="Explore", brief="b", cwd="/x")
    assert summary.agent_label(rec, "s1") == "Explore (a573f36b…)"


def test_digest_counts_tools_files_times_crimes():
    rec = AgentRecord(agent_id="", agent_type="", brief="", cwd="/p", actions=[
        Action(agent_id="", tool_name="Bash", tool_input={"command": "ls"}, ts="2026-06-01T11:49:16"),
        Action(agent_id="", tool_name="Read", tool_input={"file_path": "/p/a.py"}, ts="2026-06-01T17:30:55"),
        Action(agent_id="", tool_name="Read", tool_input={"file_path": "/p/a.py"}, ts="2026-06-01T17:31:00"),
    ])
    offs = [Offense("", "", "out_of_scope", "high", "high", "x"),
            Offense("", "", "redundant", "low", "high", "y")]
    d = summary.agent_digest(rec, offs)
    assert d["acts"] == 3
    assert d["first"] == "11:49" and d["last"] == "17:31"
    assert d["tools"] == Counter({"Read": 2, "Bash": 1})
    assert d["files"] == ["/p/a.py"]           # deduped, first-seen order
    assert d["crimes"] == Counter({"high": 1, "low": 1})


def test_format_digest_line_with_crimes():
    d = {"acts": 53, "first": "11:49", "last": "17:30",
         "tools": Counter({"Bash": 24, "Edit": 12, "Read": 9, "Write": 5}),
         "files": [], "crimes": Counter({"critical": 1, "high": 6})}
    line = summary.format_digest_line(d, emoji=False)
    assert line.startswith("53 acts · 11:49–17:30 · ")
    assert "Bash×24 Edit×12 Read×9" in line   # top 3 only
    assert "1 critical" in line and "6 high" in line


def test_format_digest_line_clean_and_no_times():
    d = {"acts": 2, "first": None, "last": None,
         "tools": Counter({"Read": 2}), "files": [], "crimes": Counter()}
    line = summary.format_digest_line(d, emoji=False)
    assert line == "2 acts · Read×2 · clean"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_summary.py -q`
Expected: FAIL (`No module named 'agent_pd.summary'`).

- [ ] **Step 3: Implement** — create `agent_pd/summary.py`:

```python
"""Pure per-agent summary helpers for pd report: a human label and an activity digest.
No I/O. Used by report.render_markdown."""
import os
from collections import Counter

from .render import SEVERITY_STYLE

_SEV_DIGEST_ORDER = ("critical", "high", "low", "review", "info")


def agent_label(record, session_id=None) -> str:
    if not record.agent_id:                        # the main (top-level) agent
        label = "main"
        proj = os.path.basename((record.cwd or "").rstrip("/"))
        if proj:
            label += f" · {proj}"
        if session_id:
            label += f" (session {session_id[:7]})"
        return label
    return f"{record.agent_type or '?'} ({record.agent_id[:8]}…)"


def _hhmm(ts) -> str:
    s = str(ts)
    return s.split("T", 1)[1][:5] if "T" in s else s[:5]


def agent_digest(record, agent_offenses) -> dict:
    tss = [a.ts for a in record.actions if a.ts]
    files, seen = [], set()
    for a in record.actions:
        ti = a.tool_input or {}
        p = ti.get("file_path") or ti.get("notebook_path")
        if p and p not in seen:
            seen.add(p)
            files.append(p)
    return {
        "acts": len(record.actions),
        "first": _hhmm(min(tss)) if tss else None,
        "last": _hhmm(max(tss)) if tss else None,
        "tools": Counter(a.tool_name for a in record.actions if a.tool_name),
        "files": files,
        "crimes": Counter(o.severity for o in agent_offenses),
    }


def format_digest_line(digest, emoji=True) -> str:
    bits = [f"{digest['acts']} acts"]
    if digest["first"]:
        bits.append(digest["first"] if digest["first"] == digest["last"]
                    else f"{digest['first']}–{digest['last']}")
    top = sorted(digest["tools"].items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    if top:
        bits.append(" ".join(f"{n}×{c}" for n, c in top))
    crimes = digest["crimes"]
    if sum(crimes.values()):
        cb = []
        for sev in _SEV_DIGEST_ORDER:
            n = crimes.get(sev, 0)
            if n:
                _, em, _ = SEVERITY_STYLE.get(sev, (sev, "•", ""))
                cb.append(f"{n}{em}" if emoji else f"{n} {sev}")
        bits.append(" ".join(cb))
    else:
        bits.append("clean")
    return " · ".join(bits)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `python3 -m pytest tests/test_summary.py -q`
Expected: PASS. Then `python3 -m pytest -q` — green.

- [ ] **Step 5: Commit**

```bash
git add agent_pd/summary.py tests/test_summary.py
git commit -m "feat(summary): pure agent_label + agent_digest + format_digest_line helpers"
```

---

## Task 2: Detectors emit full evidence (truncation moves to render)

**Files:** Modify `agent_pd/detectors/permission_bypass.py`, `agent_pd/detectors/redundant.py`, `agent_pd/detectors/off_task.py`; Test the three corresponding test files.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_permission_bypass.py`:

```python
def test_long_command_evidence_is_full():
    rules = load_rules(None)
    long_cmd = "sudo echo " + "x" * 300
    rec = _rec([Action(agent_id="a1", tool_name="Bash", tool_input={"command": long_cmd})])
    offs = permission_bypass.detect(rec, rules)
    assert len(offs) == 1
    assert "x" * 300 in offs[0].evidence    # full, not truncated
    assert "…" not in offs[0].evidence
```
Append to `tests/test_redundant.py`:
```python
def test_long_duplicate_evidence_is_full():
    from agent_pd.models import Action, AgentRecord
    from agent_pd.config import load_rules
    from agent_pd.detectors import redundant
    rules = load_rules(None)
    long_cmd = "echo " + "y" * 300
    rec = AgentRecord(agent_id="a1", agent_type="x", brief="b", cwd="/p", actions=[
        Action(agent_id="a1", tool_name="Bash", tool_input={"command": long_cmd}),
        Action(agent_id="a1", tool_name="Bash", tool_input={"command": long_cmd}),
    ])
    offs = redundant.detect(rec, rules)
    assert len(offs) == 1
    assert "y" * 300 in offs[0].evidence
    assert "…" not in offs[0].evidence
```
Append to `tests/test_off_task.py`:
```python
def test_long_query_evidence_is_full():
    from agent_pd.models import Action, AgentRecord
    from agent_pd.config import load_rules
    from agent_pd.detectors import off_task
    rules = load_rules(None)
    q = "z" * 200
    rec = AgentRecord(agent_id="a1", agent_type="x", brief="fix the parser", cwd="/p",
                      actions=[Action(agent_id="a1", tool_name="Grep", tool_input={"pattern": q})])
    offs = off_task.detect(rec, rules)
    assert len(offs) == 1
    assert q in offs[0].evidence and "…" not in offs[0].evidence
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_permission_bypass.py::test_long_command_evidence_is_full tests/test_redundant.py::test_long_duplicate_evidence_is_full tests/test_off_task.py::test_long_query_evidence_is_full -q`
Expected: FAIL (current code truncates with `…`).

- [ ] **Step 3a: permission_bypass** — in `agent_pd/detectors/permission_bypass.py`, change `_summ` to not truncate:
```python
def _summ(tool_input: dict) -> str:
    return json.dumps(tool_input, sort_keys=True)
```
(Remove the `limit` parameter and the truncation. The two call sites `_summ(a.tool_input)` still work since they pass only one arg.)

- [ ] **Step 3b: redundant** — in `agent_pd/detectors/redundant.py`, replace the truncation line in `detect` (`payload = key[1] if len(key[1]) <= 120 else key[1][:120] + "…"`) with:
```python
            payload = key[1]
```

- [ ] **Step 3c: off_task** — in `agent_pd/detectors/off_task.py`, in `detect`, replace the truncation block:
```python
            term = q if len(q) <= 50 else q[:49] + "…"
            brief = record.brief if len(record.brief) <= 50 else record.brief[:49] + "…"
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "low",
                               f"searched '{term}' — {overlap:.0%} word-overlap with "
                               f"brief '{brief}'", subject=q))
```
with:
```python
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "low",
                               f"searched '{q}' — {overlap:.0%} word-overlap with "
                               f"brief '{record.brief}'", subject=q))
```

- [ ] **Step 4: Run tests to verify pass**

Run: `python3 -m pytest -q`
Expected: PASS (the 3 new tests + full suite). If any EXISTING test asserted a truncated form (`…`), update it to assert the full substring instead — report any such change. (The current tests assert substrings/severity, so they should already pass unchanged.)

- [ ] **Step 5: Commit**

```bash
git add agent_pd/detectors/permission_bypass.py agent_pd/detectors/redundant.py agent_pd/detectors/off_task.py \
        tests/test_permission_bypass.py tests/test_redundant.py tests/test_off_task.py
git commit -m "refactor(detectors): emit full evidence; truncation now belongs to the render layer"
```

---

## Task 3: `report.py` — named header, digest line, render-layer truncation, files list

**Files:** Rewrite `agent_pd/report.py`; Modify `agent_pd/cli.py`; Test `tests/test_report.py`.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_report.py`:

```python
def test_main_agent_named_with_project_and_digest():
    recs = [AgentRecord(agent_id="", agent_type="", brief="", cwd="/Users/x/agent-pd",
                        actions=[Action(agent_id="", tool_name="Bash",
                                        tool_input={"command": "ls"}, ts="2026-06-01T11:49:00")])]
    md = render_markdown(recs, [], session_id="339f8c25-aa")
    assert "### main · agent-pd (session 339f8c2)" in md
    assert "1 acts" in md            # digest line present even with no offenses


def test_evidence_truncated_by_default_full_in_verbose():
    long_ev = "Bash: " + "x" * 300
    recs = [AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/x")]
    offs = [Offense("a1", "Explore", "permission_bypass", "critical", "high", long_ev)]
    md = render_markdown(recs, offs)
    assert "…" in md and ("x" * 300) not in md
    md_v = render_markdown(recs, offs, verbose=True)
    assert ("x" * 300) in md_v


def test_verbose_lists_files_touched():
    recs = [AgentRecord(agent_id="", agent_type="", brief="", cwd="/p", actions=[
        Action(agent_id="", tool_name="Read", tool_input={"file_path": "/etc/hosts"})])]
    md = render_markdown(recs, [], verbose=True)
    assert "files: /etc/hosts" in md


def test_agent_focus_lists_actions():
    recs = [AgentRecord(agent_id="a573f36bxyz", agent_type="Explore", brief="find foo", cwd="/x",
                        actions=[Action(agent_id="a573f36bxyz", tool_name="Grep",
                                        tool_input={"pattern": "foo"}, ts="2026-06-01T12:00:00")]),
            AgentRecord(agent_id="b1", agent_type="Plan", brief="", cwd="/x")]
    md = render_markdown(recs, [], session_id="s1", only_agent="a573f36b")
    assert "Explore (a573f36b…)" in md
    assert "Plan" not in md           # focused on just the one agent
    assert "### actions" in md
    assert "Grep" in md and "foo" in md


def test_agent_focus_not_found():
    recs = [AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/x")]
    md = render_markdown(recs, [], session_id="s1", only_agent="zzz")
    assert "no agent matching 'zzz'" in md
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_report.py -q`
Expected: FAIL (`render_markdown` has no `session_id`/`verbose`/`only_agent` params; no digest/focus).

- [ ] **Step 3: Implement** — replace the whole of `agent_pd/report.py` with:

```python
import json
from dataclasses import asdict

from .summary import agent_label, agent_digest, format_digest_line
from .render import action_summary, _fmt_ts

_SEV_ORDER = {"critical": 0, "high": 1, "low": 2, "review": 3, "info": 4}
_MD_EVIDENCE_LIMIT = 120


def render_json(offenses: list) -> str:
    return json.dumps([asdict(o) for o in offenses], indent=2)


def _ev_cell(evidence: str, verbose: bool) -> str:
    s = evidence.replace("|", "\\|")
    if not verbose and len(s) > _MD_EVIDENCE_LIMIT:
        s = s[:_MD_EVIDENCE_LIMIT] + "…"
    return s


def _offense_table(offs: list, verbose: bool) -> list:
    lines = ["", "| severity | offense | confidence | evidence |",
             "|----------|---------|------------|----------|"]
    for o in sorted(offs, key=lambda o: _SEV_ORDER.get(o.severity, 9)):
        lines.append(f"| {o.severity} | {o.offense} | {o.confidence} | {_ev_cell(o.evidence, verbose)} |")
    return lines


def _matches(record, only_agent: str) -> bool:
    if only_agent == "main":
        return record.agent_id == ""
    return bool(record.agent_id) and record.agent_id.startswith(only_agent)


def _render_focus(matches: list, by_agent: dict, session_id) -> str:
    out = []
    for rec in matches:
        offs = by_agent.get(rec.agent_id, [])
        digest = agent_digest(rec, offs)
        out.append(f"## {agent_label(rec, session_id)}")
        if rec.brief:
            out.append(f'assigned: "{rec.brief}"')
        out.append(f"_{format_digest_line(digest)}_")
        if digest["files"]:
            out.append(f"files: {', '.join(digest['files'])}")
        if offs:
            out += _offense_table(offs, verbose=True)
        out += ["", "### actions"]
        for a in rec.actions:
            out.append(f"  {_fmt_ts(a.ts)}  {a.tool_name:<10} "
                       f"{action_summary(a.tool_name, a.tool_input, limit=100)}")
        out.append("")
    return "\n".join(out)


def render_markdown(records: list, offenses: list, session_id=None,
                    verbose: bool = False, only_agent=None) -> str:
    by_agent = {}
    for o in offenses:
        by_agent.setdefault(o.agent_id, []).append(o)

    if only_agent is not None:
        matches = [r for r in records if _matches(r, only_agent)]
        if not matches:
            return f"no agent matching '{only_agent}' in session {session_id or '(most recent)'}"
        return _render_focus(matches, by_agent, session_id)

    lines = [f"## Police report — {len(records)} agents, {len(offenses)} offense(s)", ""]
    for rec in records:
        offs = by_agent.get(rec.agent_id, [])
        digest = agent_digest(rec, offs)
        lines.append(f"### {agent_label(rec, session_id)}")
        if rec.brief:
            lines.append(f'  assigned: "{rec.brief}"')
        lines.append(f"_{format_digest_line(digest)}_")
        if verbose and digest["files"]:
            lines.append(f"  files: {', '.join(digest['files'])}")
        if offs:
            lines += _offense_table(offs, verbose)
        lines.append("")
    return "\n".join(lines)
```

- [ ] **Step 4: Wire the CLI** — in `agent_pd/cli.py`:
  - Change the investigator import to include `_latest_session`:
    `from .investigator import gather, _latest_session, DEFAULT_PROJECTS_DIR, DEFAULT_AUDIT_DIR`
  - Replace `_cmd_report` with:
```python
def _cmd_report(args) -> int:
    rules = load_rules(args.rules)
    sid = args.session or _latest_session(Path(args.projects_dir), Path(args.audit_dir))
    records = gather(session_id=sid, projects_dir=args.projects_dir, audit_dir=args.audit_dir)
    offenses = []
    for rec in records:
        offenses.extend(run_detectors(rec, rules))
    if args.format in ("json", "both"):
        print(render_json(offenses))
    if args.format in ("md", "both"):
        print(render_markdown(records, offenses, session_id=sid,
                              verbose=args.verbose, only_agent=args.agent))
    return 0
```
  - In `build_parser`, in the `report` subparser block, add two arguments (after the `--audit-dir` line, before `r.set_defaults`):
```python
    r.add_argument("-v", "--verbose", action="store_true",
                   help="show full (untruncated) evidence and a files-touched list")
    r.add_argument("--agent", default=None,
                   help="focus on one agent (id prefix, or 'main') and list all its actions")
```

- [ ] **Step 5: Run tests to verify pass**

Run: `python3 -m pytest -q`
Expected: PASS. The existing `test_render_markdown_groups_by_agent` / `_escapes_pipes` still pass (they assert substrings `Explore`, `find foo`, `redundant`, `dup Grep`, escaped pipe — all retained).

- [ ] **Step 6: Commit**

```bash
git add agent_pd/report.py agent_pd/cli.py tests/test_report.py
git commit -m "feat(report): named main agent, per-agent digest, --verbose full evidence + files, --agent focus"
```

---

## Task 4: Docs + end-to-end smoke

**Files:** Modify `README.md`, `HANDOFF.md`.

- [ ] **Step 1: Full suite**

Run: `python3 -m pytest -q`
Expected: PASS. Record the total.

- [ ] **Step 2: Smoke the new report**

Run each and confirm they render without error:
```bash
python3 -m agent_pd.cli report --format md | head -20
python3 -m agent_pd.cli report --format md --verbose | head -20
python3 -m agent_pd.cli report --agent main -v | head -30
```
Expected: the first shows `### main · <project> (session …)` with an italic digest line under each agent; `--verbose` shows full evidence + a `files:` line; `--agent main -v` shows just the main agent plus a `### actions` chronological list. Paste the first ~12 lines of the `--agent main -v` output into your report.

- [ ] **Step 3: Update `README.md`** — under the `pd report` usage, document the new flags:
```
pd report --verbose            # full evidence + files-touched per agent
pd report --agent <id|main>    # focus one agent: digest + every action it took
```
And note that each agent now shows a one-line digest (acts · time span · top tools · crimes), and the main agent is named by its project + session.

- [ ] **Step 4: Update `HANDOFF.md`** — in the `report.py` file-map line, note it now renders the per-agent digest + `--verbose`/`--agent`; update the test-count mentions to the Step 1 total (3 places). Add a one-line note that `summary.py` holds the pure label/digest helpers.

- [ ] **Step 5: Commit**

```bash
git add README.md HANDOFF.md
git commit -m "docs: document pd report digest, --verbose, and --agent focus"
```

---

## Self-review notes (author)

- **Spec coverage:** §1 label+digest → Task 1 (summary.py) + rendered in Task 3; §2 `--verbose` full evidence → Task 2 (detectors emit full) + Task 3 (render truncates by default); §3 `--agent` focus → Task 3 (`_render_focus`); §4 files-touched → Task 3 (verbose branch + focus). CLI wiring → Task 3 Step 4. Docs → Task 4. All mapped.
- **Type consistency:** `agent_label(record, session_id=None)`, `agent_digest(record, agent_offenses)`, `format_digest_line(digest, emoji=True)` defined in Task 1 and called identically in Task 3. `render_markdown(records, offenses, session_id=None, verbose=False, only_agent=None)` defined in Task 3, called with those kwargs by `cli._cmd_report` (Task 3 Step 4). `_summ(tool_input)` (Task 2) keeps its single-arg call sites. `_fmt_ts`/`action_summary` imported from `render` (exist).
- **No placeholders:** every step has complete code.
```
