from agent_pd.models import Offense
from agent_pd.render import (
    Style, action_summary, badge, agent_tag, format_banner,
    format_feed_line, format_rap_sheet, _fmt_ts,
)


def test_fmt_ts_handles_missing_and_iso():
    assert _fmt_ts(None) == "--:--:--"
    assert _fmt_ts("") == "--:--:--"
    assert _fmt_ts("2026-06-01T12:01:06") == "12:01:06"
    assert _fmt_ts("12:00") == "12:00"


def test_action_summary_per_tool():
    assert action_summary("Bash", {"command": "sudo rm"}) == "sudo rm"
    assert action_summary("Grep", {"pattern": "foo"}) == "foo"
    assert action_summary("Write", {"file_path": "src/a.py"}) == "src/a.py"
    assert action_summary("WebFetch", {"url": "http://x/y", "prompt": "p"}) == "http://x/y"
    assert action_summary("WebSearch", {"query": "q terms"}) == "q terms"


def test_action_summary_readable_fallback_for_other_tools():
    # tools without a dedicated formatter still show a clean field, not raw JSON
    assert action_summary("ToolSearch", {"query": "select:Grep", "max_results": 5}) == "select:Grep"
    assert action_summary("Task", {"description": "do a thing", "x": 1}) == "do a thing"
    # truly opaque input still falls back to JSON rather than blank
    assert action_summary("Mystery", {"a": 1}).startswith("{")


def test_action_summary_truncates_and_strips_newlines():
    s = action_summary("Bash", {"command": "echo " + "x" * 200}, limit=20)
    assert len(s) <= 20
    assert "\n" not in action_summary("Bash", {"command": "a\nb"})


def test_badge_emoji_toggle():
    with_emoji = badge("critical", Style(color=False, emoji=True))
    assert "CRITICAL" in with_emoji and "🚨" in with_emoji
    no_emoji = badge("critical", Style(color=False, emoji=False))
    assert "CRITICAL" in no_emoji and "🚨" not in no_emoji


def test_style_paint_respects_color_flag():
    assert Style(color=False).paint("x", "31") == "x"          # no ANSI when disabled
    painted = Style(color=True).paint("x", "31")
    assert painted != "x" and "x" in painted and "\033[" in painted


def test_agent_tag_abbreviates_and_shortens_id():
    assert agent_tag("general-purpose", "a55d42971949c8763") == "gp·a55d"
    assert agent_tag("Explore", "a93ccd5b9f98f6b64") == "Explore·a93c"


def test_format_banner_shows_brief():
    out = format_banner("Explore", "a93ccd", "find callers of auth()", Style(color=False))
    assert "Explore" in out
    assert "find callers of auth()" in out


def test_format_banner_without_brief_omits_brief_line():
    out = format_banner("gp", "a55d", "", Style(color=False))
    assert "brief" not in out


def test_feed_line_clean_suppressed_when_crimes_only():
    lines = format_feed_line("12:00:00", "Explore", "a93c", "Grep",
                             {"pattern": "foo"}, [], Style(color=False), crimes_only=True)
    assert lines == []


def test_feed_line_clean_shown_by_default():
    lines = format_feed_line("12:00:00", "Explore", "a93c", "Grep",
                             {"pattern": "foo"}, [], Style(color=False))
    assert len(lines) == 1
    assert "Grep" in lines[0] and "foo" in lines[0]


def test_feed_line_offense_shows_badge_and_reason():
    off = Offense("a55d", "gp", "permission_bypass", "critical", "high",
                  "Bash: matched escalation pattern 'sudo ' in command")
    lines = format_feed_line("12:01:06", "gp", "a55d", "Bash",
                             {"command": "sudo rm"}, [off], Style(color=False, emoji=False))
    assert "CRITICAL" in lines[0]
    # the "why" appears on an indented reason line
    assert any("escalation pattern 'sudo '" in ln for ln in lines[1:])


def test_feed_line_worst_severity_on_main_line():
    offs = [
        Offense("a", "gp", "off_task", "review", "low", "WebFetch overlap 0.0"),
        Offense("a", "gp", "permission_bypass", "critical", "high", "Bash sudo"),
    ]
    lines = format_feed_line("12:00", "gp", "a", "Bash", {"command": "sudo x"},
                             offs, Style(color=False, emoji=False))
    assert "CRITICAL" in lines[0]      # worst severity wins the headline badge
    assert len(lines) == 3             # main + 2 reason lines


def test_feed_line_verbose_shows_full_command_and_reason():
    long_ev = "reason " + "z" * 200
    off = Offense("a", "gp", "off_task", "review", "low", long_ev)
    cmd = "grep " + "y" * 200
    normal = format_feed_line("12:00", "gp", "a", "Bash", {"command": cmd}, [off],
                              Style(color=False, emoji=False))
    verbose = format_feed_line("12:00", "gp", "a", "Bash", {"command": cmd}, [off],
                               Style(color=False, emoji=False), verbose=True)
    assert "…" in "\n".join(normal)              # truncated by default
    assert long_ev in "\n".join(verbose)          # full reason shown when verbose
    assert ("y" * 200) in verbose[0]              # full command shown when verbose


def test_info_badge_renders_plain():
    from agent_pd.render import badge, Style
    b = badge("info", Style(color=False, emoji=False))
    assert "INFO" in b


def test_rap_sheet_shows_crimes_acts_and_tools():
    entries = [
        {"tag": "gp·a55d", "color": "31", "crimes": {"critical": 1, "high": 1},
         "acts": 9, "tools": {"Bash": 5, "Grep": 4}},
        {"tag": "Explore·a93c", "color": "32", "crimes": {},
         "acts": 14, "tools": {"Grep": 14}},
    ]
    out = format_rap_sheet(entries, total_acts=23, style=Style(color=False, emoji=False))
    assert "gp·a55d" in out and "Explore·a93c" in out
    assert "23 acts" in out            # session total in header
    assert "2 crimes" in out           # total crimes (1 critical + 1 high)
    assert "Grep×14" in out            # per-agent activity is shown even when clean
    assert "clean" in out              # the no-crime agent is labeled


def test_rap_sheet_clean_agent_still_shows_activity():
    entries = [{"tag": "workflow-subagent·a85f", "color": "36", "crimes": {},
                "acts": 14, "tools": {"Grep": 6, "Read": 5, "Bash": 3}}]
    out = format_rap_sheet(entries, total_acts=14, style=Style(color=False, emoji=False))
    assert "14 acts" in out and "Grep×6" in out and "Read×5" in out


def test_info_only_feed_line_hidden_under_crimes_only():
    from agent_pd.render import format_feed_line, Style
    from agent_pd.models import Offense
    o = Offense("a1", "gp", "out_of_scope", "info", "high", "x (permitted by allow-rule)")
    plain = Style(color=False, emoji=False)
    # hidden under --crimes-only (permitted, not a crime)
    assert format_feed_line("t", "gp", "a1", "Bash", {"command": "cat /x"}, [o],
                            plain, crimes_only=True) == []
    # but visible in the normal feed, badged INFO
    lines = format_feed_line("t", "gp", "a1", "Bash", {"command": "cat /x"}, [o],
                             plain, crimes_only=False)
    assert lines and "INFO" in lines[0]


def test_real_crime_still_shown_under_crimes_only():
    from agent_pd.render import format_feed_line, Style
    from agent_pd.models import Offense
    o = Offense("a1", "gp", "out_of_scope", "high", "high", "Bash touched /etc (outside project)")
    lines = format_feed_line("t", "gp", "a1", "Bash", {"command": "cat /etc/x"}, [o],
                             Style(color=False, emoji=False), crimes_only=True)
    assert lines  # not hidden


def test_rap_sheet_info_not_counted_as_crime():
    from agent_pd.render import format_rap_sheet, Style
    entries = [{"tag": "gp·a1", "color": "37", "crimes": {"info": 2}, "acts": 3, "tools": {"Bash": 3}}]
    out = format_rap_sheet(entries, 3, Style(color=False, emoji=False))
    assert "0 crimes" in out      # info excluded from the crime total
    assert "clean" not in out     # but not 'clean' — the 2 info items are shown
    assert "2 info" in out
