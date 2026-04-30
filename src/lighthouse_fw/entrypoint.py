"""Entrypoint that dispatches to TUI by default and CLI when arguments are supplied."""

from __future__ import annotations

import sys

from .cli import app
from .tui import run_tui


def main() -> None:
    """Open the TUI when no args are given; otherwise hand off to Typer."""

    if len(sys.argv) == 1:
        run_tui()
        return
    app(prog_name="lhfw")

