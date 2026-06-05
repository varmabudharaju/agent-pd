# agent-pd — Architecture & System Design

A visual, step-by-step walk through how agent-pd works, grounded in the actual code.
The diagrams are [Mermaid](https://mermaid.js.org/) — they render as images on GitHub and
in most Markdown viewers (VS Code, Obsidian, etc.). **Pre-rendered PNGs** of every diagram
(for slides/docs) live in [`docs/diagrams/`](docs/diagrams/README.md).

**One-sentence model:** a logging-only **hook** records every Claude Code tool call to a
per-session, hash-chained **audit log**; the **`pd` CLI** replays that log through six
**detectors** and reports rule offenses with quoted evidence. It *detects and reports* — it
never blocks.

---

## 1. System context — who talks to what

The big picture: where agent-pd sits relative to Claude Code, the disk, and you.

```mermaid
flowchart TB
    subgraph CC["Claude Code (main agent + subagents)"]
        TOOL["Every tool call<br/>(Bash, Read, Write, Edit, Task, …)"]
    end

    HOOK["pd hook<br/>(agent_pd/hook.py)<br/>logging-only · always exit 0"]
    LOG[("Audit log<br/>~/.claude/pd/audit/&lt;sid&gt;.jsonl<br/>hash-chained, one file per session")]

    subgraph PD["pd CLI (agent_pd/cli.py)"]
        REPORT["pd report<br/>(forensic)"]
        WATCH["pd watch<br/>(live scanner)"]
        VERIFY["pd verify<br/>(tamper check)"]
        COMPACT["pd compact<br/>(gzip old logs)"]
        SINK["pd sink<br/>(off-host copy)"]
        JUDGE["pd judge<br/>(opt-in LLM)"]
    end

    USER(["You (terminal)"])
    OFFHOST[("Off-host sink<br/>file / http (append-only)")]
    LLM["Anthropic API or<br/>claude CLI (subscription)"]

    TOOL -- "PostToolUse / PermissionDenied /<br/>SubagentStart / SubagentStop" --> HOOK
    HOOK -- "append one normalized,<br/>chained event" --> LOG
    LOG --> REPORT & WATCH & VERIFY & COMPACT & SINK & JUDGE
    REPORT & WATCH & VERIFY --> USER
    SINK -- "forward un-sent events" --> OFFHOST
    JUDGE -- "confirm off_task flags" --> LLM
    LLM --> JUDGE

    classDef hook fill:#ffe9c7,stroke:#b06f00;
    classDef store fill:#d7ecff,stroke:#1769aa;
    class HOOK hook
    class LOG,OFFHOST store
```

**Read it in one breath:** Claude Code fires a hook event on every tool call → the hook
appends a chained line to the session's audit log → the `pd` commands read that log to
report, watch, verify, compact, or forward it. The hook is the *only* writer; everything
else reads.

---

## 2. The two phases — capture vs. read

agent-pd has a deliberately dumb **write path** and a smart **read path**. They are
decoupled by the audit log on disk.

```mermaid
flowchart LR
    subgraph CAPTURE["CAPTURE — automatic, all sessions, zero intelligence"]
        direction TB
        E["hook event<br/>(JSON on stdin)"] --> BE["build_event()<br/>normalize fields"]
        BE --> CH["integrity.next_link()<br/>seq + chain hash"]
        CH --> AP["append line +<br/>update &lt;sid&gt;.head.json"]
    end

    LOG[("~/.claude/pd/audit/<br/>&lt;sid&gt;.jsonl(.gz)")]

    subgraph READ["READ — on demand, all the intelligence, zero tokens"]
        direction TB
        IT["store.iter_events()<br/>.jsonl + .jsonl.gz"] --> GA["investigator.gather()<br/>→ AgentRecords"]
        GA --> DET["run_detectors()<br/>6 detectors"]
        DET --> RND["render / report / live feed"]
    end

    AP --> LOG --> IT

    classDef cap fill:#ffe9c7,stroke:#b06f00;
    classDef rd fill:#e7f7e7,stroke:#2e7d32;
    class CAPTURE cap
    class READ rd
```

**Why split this way?**
- The hook must be **crash-safe and fast** — it runs on *every* tool call and must never
  break your agent. So it only normalizes + chains + appends, then exits 0.
- All the analysis (correlation, detection, rendering) happens later in the CLI, where it
  can be as smart as it likes and costs nothing on the hot path.
- **Denied calls only exist in the audit log** — Claude Code kills them before they reach
  the transcript — which is *why* the hook exists instead of just parsing transcripts.

---

## 3. Component diagram — the modules and how they depend

Every box is a real file under `agent_pd/`. Arrows mean "uses / calls".

```mermaid
flowchart TD
    CLI["cli.py<br/>argparse dispatch"]

    subgraph WRITE["Write path"]
        HOOK["hook.py<br/>recorder"]
        INTEG["integrity.py<br/>hash-chain + head + lock"]
        INSTALL["install_hook.py<br/>register in settings.json"]
    end

    subgraph READMODELS["Read path"]
        STORE["store.py<br/>iter_events · compact · gz"]
        INVEST["investigator.py<br/>gather()"]
        LIVE["live.py<br/>LiveMonitor · watch()"]
        REPORT["report.py<br/>render_json / render_markdown"]
        RENDER["render.py<br/>live feed formatting"]
        SUMMARY["summary.py<br/>labels / digests"]
    end

    subgraph DETECTORS["detectors/ (6)"]
        D1["permission_bypass"]
        D2["out_of_scope"]
        D3["self_permission"]
        D4["tool_scope<br/>(tool_not_allowed)"]
        D5["redundant"]
        D6["off_task"]
    end

    subgraph SHARED["Shared logic"]
        SCOPE["scope.py<br/>path extraction/classify"]
        PERM["permissions.py<br/>allow-rule matching"]
        AGENTS["agents_def.py<br/>subagent tool allowlists"]
        CONFIG["config.py<br/>rules + sensitive set"]
        MODELS["models.py<br/>Action · AgentRecord · Offense"]
    end

    JUDGE["judge.py<br/>opt-in off_task LLM"]
    SINK["sink.py<br/>off-host forwarder"]

    HOOK --> INTEG
    CLI --> HOOK & STORE & INVEST & LIVE & REPORT & JUDGE & SINK & INSTALL & INTEG
    INVEST --> STORE & LIVE
    LIVE --> DETECTORS & PERM & AGENTS & SUMMARY
    REPORT --> DETECTORS & SUMMARY
    D2 --> SCOPE & PERM
    D1 --> PERM
    D3 --> SCOPE
    D4 --> AGENTS
    DETECTORS --> MODELS & CONFIG
    SINK --> INTEG
```

**The dependency story:**
- `cli.py` is the switchboard — it routes each subcommand to its module.
- The **write path** (`hook.py` → `integrity.py`) is tiny and self-contained.
- The **read path** funnels through `store.iter_events` → `investigator.gather` →
  `LiveMonitor` → `run_detectors` → `render`.
- The **six detectors** lean on shared logic: `scope.py` (is this path in/out of bounds,
  sensitive?), `permissions.py` (did the user allow it?), `agents_def.py` (is this tool in
  the subagent's allowlist?), and `config.py` (the rules + sensitive list).

---

## 4. Sequence — how the hook records one tool call

What happens, in order, every single time an agent uses a tool.

```mermaid
sequenceDiagram
    autonumber
    participant CC as Claude Code
    participant H as hook.py (main)
    participant I as integrity.py
    participant FS as [sid].jsonl + .head.json

    CC->>H: tool event JSON on stdin
    Note over H: build_event() — read fields defensively<br/>(snake_case + camelCase), force decision=deny<br/>on PermissionDenied, stash unknown keys in _extra
    H->>FS: acquire per-session flock (serialize subagents)
    H->>I: read head (prev seq, prev chain)
    I-->>H: prev_link
    Note over I: chain = sha256(prev_chain + canonical(event))<br/>or HMAC-SHA256 if PD_AUDIT_KEY set
    H->>FS: append chained line, update [sid].head.json
    H->>FS: release flock
    H-->>CC: exit 0 (ALWAYS)

    rect rgb(255,235,235)
    Note over H,FS: On ANY failure (lock, head IO, hashing) it falls back to<br/>appending the ORIGINAL unchained event — never lost, exit code always 0
    end
```

**Key invariants visible here:**
- The hook **always exits 0** — it can never break your agent run.
- Events are **never lost** — if chaining fails, the raw event is still appended (it just
  shows up as a chain discontinuity in `pd verify`).
- A **per-session file lock** serializes concurrent subagents so the chain can't fork.
- `PermissionDenied` is forced to `decision=deny` from the event name — a denial is a
  denial even if a field says otherwise.

---

## 5. Sequence — what `pd report` does

The forensic read path, end to end.

```mermaid
sequenceDiagram
    autonumber
    participant U as You
    participant CLI as cli.py (_cmd_report)
    participant S as store.iter_events
    participant M as LiveMonitor (live.py)
    participant D as run_detectors
    participant R as report.py

    U->>CLI: pd report --session [sid]
    CLI->>S: read [sid].jsonl (+ .jsonl.gz), dedup
    S-->>CLI: ordered events
    loop per event
        CLI->>M: process(event, rules)
        Note over M: create or update the AgentRecord — load brief (meta.json),<br/>allow_rules (settings), tool_allowlist (from the agent definition),<br/>then append an Action
    end
    M-->>CLI: AgentRecords (main + each subagent)
    loop per record
        CLI->>D: run_detectors(record, rules)
        D-->>CLI: Offenses (with severity + evidence)
    end
    CLI->>R: render_markdown(records, offenses)
    R-->>U: police report (per-agent digest + offense tables)
```

`pd watch` is the **same pipeline**, except `LiveMonitor` *tails* the live `.jsonl` and
runs the detectors as each event arrives, printing a feed line + rap sheet instead of a
final report. One engine, two front-ends.

---

## 6. The detector pipeline — turning an Action into Offenses

For each `AgentRecord`, all six detectors run; each emits zero or more `Offense`s.

```mermaid
flowchart TD
    REC["AgentRecord<br/>(actions + brief + allow_rules + tool_allowlist)"]

    REC --> P1 & P2 & P3 & P4 & P5 & P6

    P1["permission_bypass<br/>denied calls + 2-tier Bash regex<br/>(never-downgrade vs escalation)"]
    P2["out_of_scope<br/>file/Bash path outside project<br/>OR sensitive path/credential file"]
    P3["self_permission<br/>write to own control files<br/>(.claude/*, pd-rules.yaml)"]
    P4["tool_not_allowed<br/>subagent tool ∉ declared allowlist"]
    P5["redundant<br/>exact-duplicate tool calls"]
    P6["off_task<br/>search vs brief word-overlap<br/>(heuristic)"]

    P1 & P2 --> SEV{"matches a permission<br/>allow-rule?"}
    SEV -- "yes (and not sensitive/<br/>catastrophic)" --> INFO["downgrade to info<br/>(not a crime)"]
    SEV -- "no" --> FULL["full severity<br/>(critical / high)"]
    P3 & P4 & P5 --> FULL
    P6 --> REVIEW["review (low)<br/>→ pd judge to confirm"]

    INFO & FULL & REVIEW --> OUT["Offense list<br/>(agent, severity, confidence, evidence)"]

    classDef crit fill:#ffd9d9,stroke:#c62828;
    classDef info fill:#eee,stroke:#888;
    class FULL crit
    class INFO info
```

**The severity rule (the subtle part):** an `out_of_scope` or escalation hit that matches a
permission **allow-rule** you configured is downgraded to a quiet `info` (authorized → FYI,
not a crime). **Two things are never downgraded:** sensitive-path/credential access and
categorically-catastrophic commands (`rm -rf /`, `curl | sh`, …). A denied call stays
critical no matter what.

---

## 7. Permission-aware severity — the decision tree

Exactly how a single flagged action gets its final severity.

```mermaid
flowchart TD
    A["flagged action"] --> Q1{"denied call<br/>(PermissionDenied)?"}
    Q1 -- yes --> C1["critical (never downgrade)"]
    Q1 -- no --> Q2{"sensitive path /<br/>credential file?"}
    Q2 -- yes --> C2["critical (never downgrade)"]
    Q2 -- no --> Q3{"categorically<br/>catastrophic command?"}
    Q3 -- yes --> C3["critical (never downgrade)"]
    Q3 -- no --> Q4{"matches a permission<br/>allow-rule? (faithful CC semantics:<br/>operator-split, redirect isolation,<br/>word-boundary, gitignore globs)"}
    Q4 -- yes --> I["info — permitted, not counted as a crime"]
    Q4 -- no --> F["full severity (high / critical)"]

    classDef crit fill:#ffd9d9,stroke:#c62828;
    classDef info fill:#eee,stroke:#888;
    class C1,C2,C3 crit
    class I info
```

The bias is explicit: **ambiguity → not permitted (stays flagged)**. Under-flagging is
treated as worse than over-flagging.

---

## 8. Audit-log integrity — the hash chain

Every event is linked to the previous one, so tampering is detectable.

```mermaid
flowchart LR
    H[("&lt;sid&gt;.head.json<br/>seq=N, chain=Hn")]
    E0["event seq=1<br/>chain=H1=sha256(GENESIS+e1)"]
    E1["event seq=2<br/>chain=H2=sha256(H1+e2)"]
    E2["event seq=3<br/>chain=H3=sha256(H2+e3)"]
    E0 --> E1 --> E2
    E2 -. "anchors tail" .- H

    V["pd verify<br/>recompute each link<br/>+ compare head"]
    E0 & E1 & E2 --> V
    V --> R{"intact?"}
    R -- yes --> OK["✓ chain intact (exit 0)"]
    R -- "broken link / seq gap /<br/>unchained-after-chain" --> T["✗ TAMPER (exit 2)"]
    R -- "head seq &gt; last logged" --> TR["✗ TRUNCATED (exit 2)"]

    classDef bad fill:#ffd9d9,stroke:#c62828;
    class T,TR bad
```

- `chain = sha256(prev_chain + canonical(event))`, or **HMAC-SHA256** if `PD_AUDIT_KEY` is
  set (then an attacker without the key can't forge a valid chain).
- `pd verify` catches **in-place edits, reordering, mid-deletion, tail truncation, and
  inserted unchained lines** (exit 2 on any).
- **Honest ceiling:** this is tamper-**evident**, not tamper-**proof**. A same-user agent
  can re-chain the whole file. The off-host sink (next section) closes the
  *retroactive-deletion* half of that gap. See `SECURITY.md`.

---

## 9. Off-host sink — moving the witness off the machine

```mermaid
flowchart LR
    LOG[("local &lt;sid&gt;.jsonl<br/>(chained)")]
    ST[("&lt;sid&gt;.sink<br/>last-forwarded seq")]
    PUSH["pd sink push<br/>send events where seq &gt; last"]
    DEST[("off-host sink<br/>file (WORM) / http collector<br/>append-only")]

    LOG --> PUSH
    ST --> PUSH
    PUSH -- "POST/append NDJSON<br/>(https + Bearer token, env-only)" --> DEST
    DEST -- "durably accepted" --> PUSH
    PUSH -- "advance only on success<br/>(idempotent, retries on failure)" --> ST

    DEST --> STATUS["pd sink status<br/>forwarded/last; flags<br/>⚠ remote ahead = local truncation"]
```

The hook is **untouched** — there is no network on the hot path; the local log *is* the
spool. You run `pd sink push` on a schedule or from a Stop hook. The append-only guarantee
is a **deployment requirement** the destination must enforce (pd can't); the sink stops
retroactive *deletion* of shipped events, not forging or hook-disabling.

---

## 10. Data model — the three core shapes

```mermaid
classDiagram
    class Action {
        +str agent_id
        +str tool_name
        +dict tool_input
        +str ts
        +str decision  // allow | deny | None
        +str reason
        +object tool_result
    }
    class AgentRecord {
        +str agent_id
        +str agent_type   // "main" for the main agent
        +str brief        // from meta.json (subagents only)
        +str cwd
        +list~Action~ actions
        +list allow_rules     // permissions.allow (for info-downgrade)
        +set tool_allowlist   // declared tools, or None = unrestricted
    }
    class Offense {
        +str agent_id
        +str agent_type
        +str offense      // detector name
        +str severity     // critical | high | low | review | info
        +str confidence
        +str evidence     // quoted proof
        +str subject
    }
    AgentRecord "1" o-- "many" Action : actions
    AgentRecord ..> Offense : detectors emit
```

- An **Action** is one recorded tool call.
- An **AgentRecord** is one agent (main or a subagent) with all its actions + the context
  detectors need (brief, allow-rules, tool allowlist).
- An **Offense** is one flagged finding with quoted evidence — what the report and live
  feed display.

---

## 11. On-disk layout

```
~/.claude/
├── settings.json                  # pd install-hook registers the hook here
└── pd/
    └── audit/
        ├── <sid>.jsonl            # live capture — the hook appends here
        ├── <sid>.jsonl.gz         # compacted (pd compact, gzip, lossless)
        ├── <sid>.head.json        # hash-chain tail anchor (tamper/truncation)
        ├── <sid>.lock             # per-session flock (serialize subagents)
        └── <sid>.sink             # last-forwarded seq (pd sink state)

~/.claude/projects/*/<sid>/subagents/
        └── agent-<id>.meta.json   # subagent brief (agentType + description) — read by gather()
```

Reads (`pd report`, `pd watch`) transparently handle both `.jsonl` and `.jsonl.gz` via
`store.iter_events`. The audit log lives **outside your repo**, so it's never committed by
accident — but it stores full tool inputs (which may include secrets in plaintext), so
treat it like any sensitive local file (see `SECURITY.md` → Privacy).

---

## 12. End-to-end, in words

1. **Setup (once):** `pd install-hook` adds the hook to `~/.claude/settings.json` for
   `PostToolUse`, `PermissionDenied`, `SubagentStart`, `SubagentStop`.
2. **Capture (automatic):** every tool call → hook normalizes + hash-chains + appends one
   line to `~/.claude/pd/audit/<sid>.jsonl`, then exits 0. All sessions record concurrently.
3. **Correlate (on read):** `store.iter_events` reads the log; `investigator.gather` /
   `LiveMonitor` rebuild per-agent `AgentRecord`s, attaching each agent's brief, allow-rules,
   and tool allowlist.
4. **Detect:** the six detectors run over each record, emitting `Offense`s; permission
   allow-rules downgrade non-sensitive hits to `info`.
5. **Present:** `pd report` renders a forensic markdown/JSON report; `pd watch` shows a live
   feed + rap sheet; `pd judge` optionally confirms `off_task` flags with an LLM.
6. **Protect the record:** `pd verify` proves the chain is intact; `pd compact` gzips old
   sessions losslessly; `pd sink push` forwards events off-host so they can't be quietly
   deleted later.

For the threat model and honest limitations, read `SECURITY.md`. For the formal design (goals,
components, permission model, trade-offs), read `SYSTEM-DESIGN.md`. To see it run end-to-end,
`bash examples/demo.sh`.
