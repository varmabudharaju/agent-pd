"""agent-pd — a police department for your Claude Code agents.

A logging-only hook records every tool & permission event from the main agent and its
subagents; the ``pd`` CLI replays that log through deterministic detectors and reports
rule offenses with quoted evidence. Catch-and-report — it never blocks.
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("agent-pd")
except PackageNotFoundError:        # running from a source tree with no install metadata
    __version__ = "0.1.0"

__all__ = ["__version__"]
