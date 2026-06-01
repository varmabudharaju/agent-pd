# Manual Follow-up Required

## Hook Payload Capture (Steps 4-5)

The plan calls for capturing a live hook payload by:

1. Registering a temporary probe hook in `~/.claude/settings.json`
2. Triggering a real subagent run + permission denial
3. Inspecting the dumped JSON to confirm the exact `PermissionDenied` field names

This requires an interactive Claude Code session with a real denial and **cannot be automated**. A human must perform this step manually.

### What to do

1. Add a temporary `PreToolUse` hook to `~/.claude/settings.json` that dumps stdin to a file, e.g.:
   ```json
   {
     "hooks": {
       "PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "cat > /tmp/hook-payload.json"}]}]
     }
   }
   ```
2. Trigger a subagent that attempts a denied action (e.g. a Bash command not in the allowlist).
3. Inspect `/tmp/hook-payload.json` to record exact field names (camelCase vs snake_case, nesting, etc.).
4. Remove the probe hook from `~/.claude/settings.json`.

### Why this doesn't block progress

`agent_pd/hook.py` (built in a later task) reads payload fields defensively using both camelCase and snake_case fallbacks. The exact field names refine the implementation but do not block it — the module will function correctly with either naming convention once the real payload is confirmed.
