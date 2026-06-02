import argparse
import sys
from pathlib import Path

from .config import load_rules
from .investigator import gather, DEFAULT_PROJECTS_DIR, DEFAULT_AUDIT_DIR
from .detectors import run_detectors
from .report import render_json, render_markdown
from .hook import DEFAULT_AUDIT_DIR as HOOK_AUDIT_DIR


def _cmd_report(args) -> int:
    rules = load_rules(args.rules)
    records = gather(session_id=args.session,
                     projects_dir=args.projects_dir, audit_dir=args.audit_dir)
    offenses = []
    for rec in records:
        offenses.extend(run_detectors(rec, rules))
    if args.format in ("json", "both"):
        print(render_json(offenses))
    if args.format in ("md", "both"):
        print(render_markdown(records, offenses))
    return 0


def _cmd_list(args) -> int:
    audit = Path(args.audit_dir)
    sessions = set()
    if audit.exists():
        sessions |= {p.stem for p in audit.glob("*.jsonl")}
    for sub in Path(args.projects_dir).glob("*/*/subagents"):
        sessions.add(sub.parent.name)
    for s in sorted(sessions):
        print(s)
    return 0


def _cmd_install_hook(args) -> int:
    from .install_hook import install_hook
    install_hook(Path(args.settings))
    print(f"Patrol hook installed in {args.settings}")
    return 0


def _cmd_judge(args) -> int:
    from . import judge as judge_mod
    rules = load_rules(args.rules)
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
    for o in confirmed:
        print(f"  [{o.agent_type} {o.agent_id[:8]}] '{o.subject}' — {o.evidence}")
    return 0


def _cmd_watch(args) -> int:
    from .live import watch
    from .render import Style
    style = Style(color=not args.no_color, emoji=not args.no_emoji)
    return watch(session=args.session, crimes_only=args.crimes_only, verbose=args.verbose,
                 style=style, audit_dir=args.audit_dir, projects_dir=args.projects_dir)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pd", description="Police department for Claude Code subagents")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("report", help="produce an offense report for a session")
    r.add_argument("--session", default=None)
    r.add_argument("--format", choices=["json", "md", "both"], default="both")
    r.add_argument("--rules", default=None)
    r.add_argument("--projects-dir", default=DEFAULT_PROJECTS_DIR)
    r.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR)
    r.set_defaults(func=_cmd_report)

    l = sub.add_parser("list", help="list available sessions")
    l.add_argument("--projects-dir", default=DEFAULT_PROJECTS_DIR)
    l.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR)
    l.set_defaults(func=_cmd_list)

    h = sub.add_parser("install-hook", help="register the patrol hook in settings.json")
    h.add_argument("--settings", default=str(Path.home() / ".claude" / "settings.json"))
    h.set_defaults(func=_cmd_install_hook)

    w = sub.add_parser("watch", help="live 'police scanner' feed of agent activity")
    w.add_argument("--session", default=None, help="session id (default: most recent)")
    w.add_argument("--crimes-only", action="store_true", help="hide clean actions")
    w.add_argument("-v", "--verbose", action="store_true",
                   help="show full commands and full offense reasons (no truncation)")
    w.add_argument("--no-color", action="store_true", help="disable ANSI color")
    w.add_argument("--no-emoji", action="store_true", help="disable emoji badges")
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
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
