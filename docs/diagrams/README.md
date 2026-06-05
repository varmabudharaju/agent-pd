# Architecture diagrams

Pre-rendered PNGs of every diagram in [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md).
Grab any of these for slides, docs, or posts. The `.mmd` files are the editable
[Mermaid](https://mermaid.js.org/) sources.

| # | Diagram | Shows |
|---|---------|-------|
| 1 | [System context](01-system-context.png) | Claude Code → hook → audit log → `pd` commands |
| 2 | [Two-phase flow](02-two-phase-flow.png) | dumb write path vs. smart read path |
| 3 | [Component diagram](03-component-diagram.png) | every `agent_pd/` module and its dependencies |
| 4 | [Sequence: hook records a call](04-sequence-hook-record.png) | normalize → lock → chain → append → exit 0 |
| 5 | [Sequence: `pd report`](05-sequence-pd-report.png) | iter_events → gather → detectors → render |
| 6 | [Detector pipeline](06-detector-pipeline.png) | the six detectors + severity assignment |
| 7 | [Permission-aware severity](07-permission-severity.png) | the downgrade/never-downgrade decision tree |
| 8 | [Hash-chain integrity](08-hash-chain-integrity.png) | how `pd verify` detects tamper/truncation |
| 9 | [Off-host sink](09-offhost-sink.png) | forwarding the witness off-machine |
| 10 | [Data model](10-data-model.png) | `Action` / `AgentRecord` / `Offense` |

## Previews

### 1 · System context
![System context](01-system-context.png)

### 2 · Two-phase flow
![Two-phase flow](02-two-phase-flow.png)

### 3 · Component diagram
![Component diagram](03-component-diagram.png)

### 4 · Sequence — hook records a tool call
![Hook record sequence](04-sequence-hook-record.png)

### 5 · Sequence — `pd report`
![pd report sequence](05-sequence-pd-report.png)

### 6 · Detector pipeline
![Detector pipeline](06-detector-pipeline.png)

### 7 · Permission-aware severity
![Permission-aware severity](07-permission-severity.png)

### 8 · Hash-chain integrity
![Hash-chain integrity](08-hash-chain-integrity.png)

### 9 · Off-host sink
![Off-host sink](09-offhost-sink.png)

### 10 · Data model
![Data model](10-data-model.png)

## Regenerating

The PNGs are rendered from the `.mmd` sources with the Mermaid CLI:

```bash
for f in docs/diagrams/*.mmd; do
  npx -y @mermaid-js/mermaid-cli -i "$f" -o "${f%.mmd}.png" \
    -t neutral -b white --scale 3 -p docs/diagrams/.puppeteer.json
done
```

`.puppeteer.json` just passes `--no-sandbox` so headless Chromium runs in CI/sandboxes.
The `.mmd` files are extracted verbatim from the fenced ` ```mermaid ` blocks in
`ARCHITECTURE.md`, so edit the diagrams there and re-extract to keep them in sync.
