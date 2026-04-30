"""Entrypoint that dispatches to TUI by default and CLI when arguments are supplied."""

from __future__ import annotations

import sys
from pathlib import Path

from .cli import app
from .tui import run_tui


def main() -> None:
    """Open the TUI when no args are given; otherwise hand off to Typer."""

    if len(sys.argv) == 1:
        run_tui()
        return
    # Keep help/usage aligned with the actual executable name (lhfw or lighthouse-fw).
    invoked_name = Path(sys.argv[0]).stem or "lhfw"
    app(prog_name=invoked_name)

