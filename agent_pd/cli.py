import argparse
import sys
from pathlib import Path

from .config import load_rules, load_rules_auto
from .investigator import gather, _latest_session, DEFAULT_PROJECTS_DIR, DEFAULT_AUDIT_DIR
from .detectors import run_detectors
from .report import render_json, render_markdown
from .hook import DEFAULT_AUDIT_DIR as HOOK_AUDIT_DIR, resolve_audit_dir
from . import store
from . import integrity
from . import sink


def _cmd_report(args) -> int:
    rules = load_rules_auto(args.rules)
    sid = args.session or _latest_session(Path(args.projects_dir), Path(args.audit_dir))
    if sid is None:
        print(f"no sessions found in {args.audit_dir}")
        print("set PD_AUDIT_DIR or pass --audit-dir if your logs are elsewhere")
        return 0
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


def _cmd_list(args) -> int:
    import time
    from .render import home_rel
    audit = Path(args.audit_dir)
    sessions = set()
    sessions |= set(store.list_sessions(audit))
    for sub in Path(args.projects_dir).glob("*/*/subagents"):
        sessions.add(sub.parent.name)
    # One row per session with its identity (project, last activity, first prompt),
    # oldest first so the most recent session ends up next to the prompt.
    rows = [(store.session_identity(sid, audit), sid) for sid in sessions]
    rows.sort(key=lambda r: (r[0]["last_active"] or 0, r[1]))
    sid_w = max((len(sid) for _, sid in rows), default=0)
    proj_w = max((len(home_rel(i["project"])) for i, _ in rows), default=0)
    for ident, sid in rows:
        when = (time.strftime("%b %d %H:%M", time.localtime(ident["last_active"]))
                if ident["last_active"] else "")
        title = f"“{ident['title']}”" if ident["title"] else ""
        print(f"{sid:<{sid_w}}  {home_rel(ident['project']):<{proj_w}}  "
              f"{when:<12}  {title}".rstrip())
    return 0


def _cmd_install_hook(args) -> int:
    from .install_hook import install_hook
    audit_dir = getattr(args, "audit_dir", None)
    install_hook(Path(args.settings), audit_dir=audit_dir)
    where = f" (logging to {audit_dir})" if audit_dir else ""
    print(f"Patrol hook installed in {args.settings}{where}")
    return 0


def _cmd_judge(args) -> int:
    from . import judge as judge_mod
    rules = load_rules_auto(args.rules)
    records = gather(session_id=args.session,
                     projects_dir=args.projects_dir, audit_dir=args.audit_dir)
    est = judge_mod.estimate(records, rules)
    if est["items"] == 0:
        print("No off_task items to judge for this session.")
        return 0
    backend = "claude-code" if args.via_claude_code else "api"
    via = "the claude CLI (your subscription)" if args.via_claude_code else "the Anthropic API"
    if not args.run:
        print(f"[dry run] would judge {est['items']} off_task item(s) across "
              f"{est['agents']} agent(s) in {est['calls']} batched call(s) "
              f"on model '{args.model}' via {via}.")
        if not args.via_claude_code:
            print(f"  estimated ~{est['approx_input_tokens']} input + "
                  f"~{est['approx_output_tokens']} output tokens.")
        print("  re-run with --run to actually judge.")
        return 0
    if args.via_claude_code:
        if not judge_mod.have_claude_cli():
            print("Cannot run the judge: the `claude` CLI was not found on PATH. Skipping.")
            return 1
    elif not judge_mod.have_credentials():
        print("Cannot run the judge: set ANTHROPIC_API_KEY and "
              "`pip install -e \".[judge]\"` (anthropic SDK), or use --via-claude-code. Skipping.")
        return 1
    result = judge_mod.judge_records(records, rules, model=args.model,
                                     max_items=args.max, backend=backend)
    confirmed, dropped = result["confirmed"], result["dropped"]
    cost = (" (on your Claude subscription)" if args.via_claude_code
            else f" (~{result['usage']['input_tokens']}in/"
                 f"{result['usage']['output_tokens']}out tokens)")
    print(f"Judged {est['items']} flagged item(s): {len(confirmed)} confirmed off-task, "
          f"{dropped} dropped as false positives{cost}.")
    if result.get("errored"):
        print(f"  {result['errored']} item(s) could not be judged (backend error).")
    for o in confirmed:
        print(f"  [{o.agent_type} {o.agent_id[:8]}] '{o.subject}' — {o.evidence}")
    return 0


def _cmd_watch(args) -> int:
    from .live import watch
    from .render import Style
    style = Style(color=not args.no_color, emoji=not args.no_emoji)
    rules = load_rules_auto(args.rules)
    return watch(session=args.session, crimes_only=args.crimes_only, verbose=args.verbose,
                 all_sessions=args.all_sessions, style=style, rules=rules,
                 audit_dir=args.audit_dir, projects_dir=args.projects_dir, replay=args.replay)


def _cmd_compact(args) -> int:
    rules = load_rules_auto(args.rules)
    audit = Path(args.audit_dir)
    prune_days = (args.prune_older_than if args.prune_older_than is not None
                  else rules.storage["retention_days"])
    if args.dry_run:
        if args.session:
            targets = [args.session] if (audit / f"{args.session}.jsonl").exists() else []
        else:
            targets = store.compact_targets(audit)
        print(f"[dry run] would compact {len(targets)} session(s): "
              f"{', '.join(sorted(set(targets))) or '(none)'}. "
              f"re-run without --dry-run to apply.")
        return 0
    if args.session:
        n = store.compact_session(args.session, audit)
        print(f"compacted session {args.session}: {n} event(s) gzipped.")
    else:
        done = store.compact_all(audit)
        print(f"compacted {len(done)} session(s): {', '.join(done) or '(none)'} "
              f"(skipped the active session).")
    if prune_days is not None:
        removed = store.prune_sessions(audit, older_than_days=prune_days)
        if removed:
            print(f"pruned {removed} compacted session(s) older than {prune_days}d.")
    return 0


def _verify_one(sid, audit_dir) -> tuple[int, str]:
    """Verify a single session. Return (rc, message). rc 0 = ok, 2 = tamper/truncation."""
    events = list(store.iter_events(sid, audit_dir))
    result = integrity.verify_events(events, key=integrity.audit_key())

    if not result["ok"]:
        return 2, (f"✗ TAMPER DETECTED — chain breaks at seq "
                   f"{result['broken_at']} ({result['reason']})")

    # last verified seq/chain = the last chained event's seq and chain, else (0, None)
    chained = [e for e in events if integrity.SEQ_KEY in e]
    last_seq = max((e[integrity.SEQ_KEY] for e in chained), default=0)
    last_chain = chained[-1][integrity.CHAIN_KEY] if chained else None
    head_hex, head_seq = integrity.read_head(sid, audit_dir)

    if result["verified"] == 0 and head_seq == 0:
        return 0, ("⚠ no integrity data — this session predates "
                   "hash-chaining (legacy)")

    if last_seq < head_seq:
        missing = head_seq - last_seq
        return 2, (f"✗ TRUNCATED — head recorded seq {head_seq} but log ends "
                   f"at seq {last_seq} ({missing} event(s) missing from the tail)")

    # Head-anchor check: catch a tail rewrite where the chain was re-computed but the
    # head was left stale. Only compare when seqs are EQUAL — a lagging head
    # (head_seq < last_seq, the crash-before-head case) is benign and skips this.
    if head_seq == last_seq and head_seq != 0 and head_hex != last_chain:
        return 2, ("✗ TAMPER DETECTED — head anchor does not match the log tail "
                   "(chain was rewritten)")

    msg = f"✓ chain intact — {result['verified']} event(s) verified"
    if result["legacy"]:
        msg += f", {result['legacy']} legacy (pre-chain)"
    return 0, msg


def _cmd_verify(args) -> int:
    if args.all_sessions:
        sessions = store.list_sessions(args.audit_dir)
        if not sessions:
            print("no sessions found")
            return 0
        worst = 0
        for sid in sessions:
            rc, msg = _verify_one(sid, args.audit_dir)
            print(f"{sid}: {msg}")
            worst = max(worst, rc)
        return worst

    sid = args.session or store.latest_session(args.audit_dir)
    if not sid:
        print("no sessions found")
        return 0
    rc, msg = _verify_one(sid, args.audit_dir)
    print(msg)
    return rc


def _resolve_sink_sessions(args):
    """Resolve the session list for a sink command: --all, --session, or latest."""
    if args.all_sessions:
        return store.list_sessions(args.audit_dir)
    if args.session:
        return [args.session]
    sid = store.latest_session(args.audit_dir)
    return [sid] if sid else []


def _cmd_sink_push(args) -> int:
    cfg = sink.resolve_sink_config(load_rules_auto(args.rules))
    s = sink.make_sink(cfg)
    if s is None:
        print("no sink configured — set PD_SINK_TYPE=file|http "
              "(+ PD_SINK_PATH / PD_SINK_URL, PD_SINK_TOKEN). See SECURITY.md.")
        return 0

    sessions = _resolve_sink_sessions(args)
    if not sessions:
        print("no sessions")
        return 0

    failed = False
    for sid in sessions:
        try:
            r = sink.push_session(sid, args.audit_dir, s)
        except sink.SinkError as e:
            print(f"sink: {sid} — FAILED: {e}")
            failed = True
            continue
        if r["sent"] == 0 and r["pending"] == 0:
            print(f"sink: {sid} — up to date")
        else:
            print(f"sink: {sid} — sent {r['sent']} event(s) "
                  f"(forwarded through seq {r['forwarded_seq']})")
    return 2 if failed else 0


def _cmd_sink_status(args) -> int:
    sessions = _resolve_sink_sessions(args)
    if not sessions:
        print("no sessions")
        return 0
    for sid in sessions:
        forwarded = sink.read_forwarded_seq(sid, args.audit_dir)
        last = max((e.get(integrity.SEQ_KEY, 0)
                    for e in store.iter_events(sid, args.audit_dir)), default=0)
        line = f"sink: {sid} — {forwarded}/{last} forwarded"
        if forwarded > last:
            # more shipped off-host than exist locally => local truncation/tamper
            missing = forwarded - last
            line += (f" (⚠ remote ahead — {missing} local event(s) missing; "
                     "possible local tampering)")
        elif last == 0:
            line += " (no integrity data)"
        elif forwarded < last:
            line += f" ({last - forwarded} pending)"
        else:
            line += " (up to date)"
        print(line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    from . import __version__
    p = argparse.ArgumentParser(prog="pd", description="Police department for Claude Code subagents")
    p.add_argument("-V", "--version", action="version",
                   version=f"agent-pd {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    # Read commands default to the same place the hook writes: PD_AUDIT_DIR if set,
    # else ~/.claude/pd/audit. So `pd report` finds the logs without --audit-dir.
    DEFAULT_AUDIT_DIR = resolve_audit_dir()

    r = sub.add_parser("report", help="produce an offense report for a session")
    r.add_argument("--session", default=None)
    r.add_argument("--format", choices=["json", "md", "both"], default="both")
    r.add_argument("--rules", default=None,
                   help="rules file (default: auto-discover pd-rules.yaml in the cwd, "
                        "project root, or ~/.claude; else built-in defaults)")
    r.add_argument("--projects-dir", default=DEFAULT_PROJECTS_DIR)
    r.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR)
    r.add_argument("-v", "--verbose", action="store_true",
                   help="show full (untruncated) evidence and a files-touched list")
    r.add_argument("--agent", default=None,
                   help="focus on one agent (id prefix, or 'main') and list all its actions")
    r.set_defaults(func=_cmd_report)

    l = sub.add_parser("list", help="list available sessions")
    l.add_argument("--projects-dir", default=DEFAULT_PROJECTS_DIR)
    l.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR)
    l.set_defaults(func=_cmd_list)

    h = sub.add_parser("install-hook", help="register the patrol hook in settings.json")
    h.add_argument("--settings", default=str(Path.home() / ".claude" / "settings.json"))
    h.add_argument("--audit-dir", default=None,
                   help="write audit logs here instead of ~/.claude/pd/audit "
                        "(baked into the hook command; or set PD_AUDIT_DIR)")
    h.set_defaults(func=_cmd_install_hook)

    w = sub.add_parser("watch", help="live 'police scanner' feed of agent activity")
    w.add_argument("--session", default=None, help="session id (default: most recent)")
    w.add_argument("--all", dest="all_sessions", action="store_true",
                   help="merge the live feed across ALL sessions (tags each line with §session)")
    w.add_argument("--crimes-only", action="store_true", help="hide clean actions")
    w.add_argument("--replay", action="store_true",
                   help="replay the whole session's backlog first (default: stream only "
                        "new activity from now, like tail -f)")
    w.add_argument("-v", "--verbose", action="store_true",
                   help="show full commands and full offense reasons (no truncation)")
    w.add_argument("--no-color", action="store_true", help="disable ANSI color")
    w.add_argument("--no-emoji", action="store_true", help="disable emoji badges")
    w.add_argument("--rules", default=None,
                   help="rules file (default: auto-discover pd-rules.yaml; else defaults)")
    w.add_argument("--projects-dir", default=DEFAULT_PROJECTS_DIR)
    w.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR)
    w.set_defaults(func=_cmd_watch)

    j = sub.add_parser("judge", help="LLM-judge the off_task flags (opt-in, cost-capped)")
    j.add_argument("--session", default=None)
    j.add_argument("--run", action="store_true",
                   help="actually judge (default: dry-run estimate only)")
    j.add_argument("--via-claude-code", action="store_true",
                   help="judge via the `claude` CLI on your subscription (no API key)")
    j.add_argument("--model", choices=["haiku", "sonnet", "opus"], default="haiku")
    j.add_argument("--max", type=int, default=None, help="cap items judged")
    j.add_argument("--rules", default=None)
    j.add_argument("--projects-dir", default=DEFAULT_PROJECTS_DIR)
    j.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR)
    j.set_defaults(func=_cmd_judge)

    c = sub.add_parser("compact", help="gzip old session logs (lossless; skips the active session)")
    c.add_argument("--session", default=None,
                   help="compact one session (default: all but the active one)")
    c.add_argument("--prune-older-than", type=int, default=None,
                   help="also delete compacted sessions older than N days (default: keep all)")
    c.add_argument("--dry-run", action="store_true", help="report only; write nothing")
    c.add_argument("--rules", default=None)
    c.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR)
    c.set_defaults(func=_cmd_compact)

    v = sub.add_parser("verify", help="verify the audit-log hash-chain (tamper/truncation detection)")
    v.add_argument("--session", default=None)
    v.add_argument("--all", dest="all_sessions", action="store_true", help="verify every session")
    v.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR)
    v.set_defaults(func=_cmd_verify)

    sk = sub.add_parser("sink", help="forward the audit log off-host (tamper-resistance)")
    sk_sub = sk.add_subparsers(dest="sink_cmd", required=True)
    skp = sk_sub.add_parser("push", help="forward un-sent chained events to the configured sink")
    skp.add_argument("--session", default=None)
    skp.add_argument("--all", dest="all_sessions", action="store_true")
    skp.add_argument("--rules", default=None)
    skp.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR)
    skp.set_defaults(func=_cmd_sink_push)
    sks = sk_sub.add_parser("status", help="show how far each session is forwarded")
    sks.add_argument("--session", default=None)
    sks.add_argument("--all", dest="all_sessions", action="store_true")
    sks.add_argument("--rules", default=None)
    sks.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR)
    sks.set_defaults(func=_cmd_sink_status)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
