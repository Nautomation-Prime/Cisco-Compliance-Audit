"""CLI option discovery helpers used by interactive interfaces."""

from __future__ import annotations

import argparse

from rich.console import Console
from rich.table import Table


def iter_parser_options(parser: argparse.ArgumentParser) -> list[tuple[str, str, str]]:
    """Return parser options as tuples: (flags, help, default)."""
    rows: list[tuple[str, str, str]] = []
    for action in parser._actions:  # pylint: disable=protected-access
        if isinstance(action, argparse._HelpAction):  # pylint: disable=protected-access
            continue

        option_strings = action.option_strings
        if option_strings:
            flags = ", ".join(option_strings)
        else:
            flags = action.dest

        help_text = (action.help or "").replace("%(default)s", str(action.default))

        if action.default in (None, argparse.SUPPRESS):
            default_text = ""
        elif action.default == "":
            default_text = "<empty>"
        else:
            default_text = str(action.default)

        rows.append((flags, help_text, default_text))

    return rows


def render_options_table(parser: argparse.ArgumentParser) -> Table:
    """Build a Rich table containing all parser options."""
    table = Table(title="Available CLI Options", show_lines=False)
    table.add_column("Flags", style="cyan")
    table.add_column("Description", overflow="fold")
    table.add_column("Default", style="dim")

    for flags, help_text, default_text in iter_parser_options(parser):
        table.add_row(flags, help_text, default_text)

    return table


def print_options_table(
    parser: argparse.ArgumentParser, console: Console | None = None
) -> None:
    """Render parser options table to console."""
    con = console or Console()
    con.print(render_options_table(parser))
