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
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
