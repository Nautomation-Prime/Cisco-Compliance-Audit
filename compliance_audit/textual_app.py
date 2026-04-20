"""Full-screen Textual application for a premium CLI front-end."""

from __future__ import annotations

import argparse

from rich.console import Console

from .auditor import run_audit
from .cli_discovery import iter_parser_options
from .interactive_cli import launch_interactive

console = Console()


class _InteractiveChoiceApp:  # pragma: no cover - thin wrapper around Textual runtime
    def __init__(self, parser: argparse.ArgumentParser):
        self.parser = parser

    def run(self) -> str | None:
        try:
            from textual.app import App, ComposeResult
            from textual.binding import Binding
            from textual.containers import Container, Vertical
            from textual.widgets import DataTable, Footer, Header, Label, Static
        except ImportError as exc:
            raise RuntimeError(
                "Textual mode requires 'textual'. Install dependencies from requirements.txt."
            ) from exc

        parser = self.parser

        class PremiumApp(App[str]):
            CSS = """
            Screen {
                background: #0b0d12;
            }
            #hero {
                content-align: center middle;
                height: 6;
                border: round #2f8f83;
                padding: 1 2;
                color: #f5f7fa;
                background: #16202f;
            }
            #actions {
                border: round #4f6f92;
                padding: 1;
                height: 12;
                margin-top: 1;
                background: #111827;
            }
            #options {
                border: round #546e7a;
                margin-top: 1;
                height: 1fr;
            }
            """

            BINDINGS = [
                Binding("1", "interactive_wizard", "Wizard"),
                Binding("2", "quick_audit", "Quick Audit"),
                Binding("3", "show_options", "CLI Options"),
                Binding("q", "quit", "Quit"),
            ]

            def compose(self) -> ComposeResult:
                yield Header(show_clock=True)
                with Container():
                    yield Static(
                        "Cisco Compliance Audit Premium CLI\n"
                        "1) Launch Guided Wizard    2) Run Quick Audit    3) View All CLI Options    Q) Quit",
                        id="hero",
                    )
                    with Vertical(id="actions"):
                        yield Label("Action Hints")
                        yield Label("Press 1 to open the Questionary wizard.")
                        yield Label(
                            "Press 2 to run python -m compliance_audit equivalent defaults."
                        )
                        yield Label(
                            "Press 3 to inspect every available argparse option."
                        )
                    yield DataTable(id="options")
                yield Footer()

            def on_mount(self) -> None:
                table = self.query_one("#options", DataTable)
                table.add_columns("Flags", "Description", "Default")
                for flags, help_text, default_text in iter_parser_options(parser):
                    table.add_row(flags, help_text, default_text)
                table.cursor_type = "row"

            def action_interactive_wizard(self) -> None:
                self.exit("wizard")

            def action_quick_audit(self) -> None:
                self.exit("quick-audit")

            def action_show_options(self) -> None:
                table = self.query_one("#options", DataTable)
                table.focus()

        app = PremiumApp()
        return app.run()


def launch_textual(parser: argparse.ArgumentParser) -> None:
    """Launch full-screen Textual UI and route selected action."""
    app = _InteractiveChoiceApp(parser)
    choice = app.run()

    if choice == "wizard":
        launch_interactive(parser)
        return

    if choice == "quick-audit":
        console.print("Running quick audit with defaults...")
        results = run_audit(
            config_path="compliance_config",
            device_overrides=None,
            skip_jump=False,
            categories=None,
            tags_filter=None,
            min_severity=None,
            output_dir=None,
            csv_report=None,
            inventory_path=None,
        )
        if any(r.fail_count > 0 for r in results):
            console.print("Quick audit completed with compliance failures.")
        else:
            console.print("Quick audit completed with no compliance failures.")
        return

    console.print("Exited Textual mode.")
