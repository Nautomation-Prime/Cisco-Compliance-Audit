"""Full-screen Textual application for Cisco Compliance Audit."""

from __future__ import annotations

import argparse
import logging
import os
from typing import List, Optional

from rich.markup import escape as markup_escape
from textual import on, work

from .version import get_version
from .logging_setup import configure_logging
from .credentials import load_dotenv
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Static,
)

log = logging.getLogger(__name__)

# Loggers that produce very high-volume DEBUG output — suppress to WARNING in the TUI
_NOISY_LOGGERS = (
    "paramiko",
    "paramiko.transport",
    "netmiko.base_connection",
    "netmiko.utilities",
)


# ---------------------------------------------------------------------------
# Log handler
# ---------------------------------------------------------------------------

class TUILogHandler(logging.Handler):
    """Pipes log records into the RichLog widget on the audit screen."""

    _LEVEL_MARKUP = {
        logging.DEBUG:    "dim",
        logging.WARNING:  "bold yellow",
        logging.ERROR:    "bold red",
        logging.CRITICAL: "bold white on red",
    }

    def __init__(self, app: App) -> None:
        super().__init__()
        self._app = app
        self.setFormatter(
            logging.Formatter(
                "%(asctime)s  %(levelname)-8s  %(message)s",
                datefmt="%H:%M:%S",
            )
        )

    def emit(self, record: logging.LogRecord) -> None:
        try:
            text = self.format(record)
            style = self._LEVEL_MARKUP.get(record.levelno, "")
            # Escape any Rich markup characters so patterns like "[hostname]"
            # are rendered literally rather than as markup tags.
            escaped = markup_escape(text)
            markup = f"[{style}]{escaped}[/]" if style else escaped

            def _append() -> None:
                try:
                    self._app.query_one("#audit-log", RichLog).write(markup)
                except Exception:
                    pass  # Widget may not be mounted yet

            self._app.call_from_thread(_append)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Setup screen
# ---------------------------------------------------------------------------

class SetupScreen(Screen):
    """Form for entering audit configuration and credentials."""

    BINDINGS = [Binding("ctrl+q", "app.quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with ScrollableContainer(id="setup-outer"):
            with Container(id="setup-inner"):
                yield Static("Cisco Compliance Audit", id="app-title")

                # ── Audit configuration ───────────────────────────────────
                yield Label("─── Audit Configuration", classes="section-label")
                yield Label("Config File", classes="field-label")
                yield Input(
                    value="compliance_config.yaml",
                    placeholder="Path to compliance YAML config",
                    id="config-path",
                )
                yield Label(
                    "Inventory File  (optional — leave blank to use devices.yaml)",
                    classes="field-label",
                )
                yield Input(
                    placeholder="Path to inventory YAML",
                    id="inventory-path",
                )
                yield Label(
                    "Device Overrides  (optional — comma-separated IPs or hostname:IP)",
                    classes="field-label",
                )
                yield Input(
                    placeholder="e.g. 10.0.0.1, SW1:10.0.0.2",
                    id="devices",
                )
                yield Label(
                    "Categories  (optional — space or comma-separated, blank for all)",
                    classes="field-label",
                )
                yield Input(
                    placeholder="e.g. management_plane control_plane",
                    id="categories",
                )
                yield Label(
                    "Output Directory  (optional — overrides config file setting)",
                    classes="field-label",
                )
                yield Input(
                    placeholder="e.g. ./reports",
                    id="output-dir",
                )
                yield Checkbox("Skip jump / bastion host", id="skip-jump", value=False)

                # ── Credentials ───────────────────────────────────────────
                yield Label("─── Credentials", classes="section-label")
                yield Label("Username", classes="field-label")

                # Pre-fill from .env / environment if available
                load_dotenv()
                _env_user = (
                    os.environ.get("SWITCH_USER")
                    or os.environ.get("CREDENTIAL_USER")
                    or ""
                )
                _env_pass = (
                    os.environ.get("SWITCH_PASS")
                    or os.environ.get("CREDENTIAL_PASS")
                    or ""
                )

                yield Input(
                    value=_env_user,
                    placeholder="SSH username",
                    id="username",
                )
                yield Label("Password", classes="field-label")
                yield Input(
                    value=_env_pass,
                    placeholder="SSH password",
                    password=True,
                    id="password",
                )

                # ── Buttons ───────────────────────────────────────────────
                with Horizontal(id="btn-row"):
                    yield Button("Start Audit", variant="primary", id="btn-start")
                    yield Button("Quit", variant="error", id="btn-quit")

        yield Footer()

    @on(Button.Pressed, "#btn-start")
    def _on_start(self) -> None:
        """Validate form inputs and transition to the audit screen."""
        config_path = (
            self.query_one("#config-path", Input).value.strip()
            or "compliance_config.yaml"
        )
        inventory_path = self.query_one("#inventory-path", Input).value.strip() or None
        devices_raw = self.query_one("#devices", Input).value.strip()
        categories_raw = self.query_one("#categories", Input).value.strip()
        output_dir = self.query_one("#output-dir", Input).value.strip() or None
        skip_jump = self.query_one("#skip-jump", Checkbox).value
        username = self.query_one("#username", Input).value.strip()
        password = self.query_one("#password", Input).value

        if not username:
            self.notify("Username is required.", severity="error")
            return
        if not password:
            self.notify("Password is required.", severity="error")
            return

        device_overrides = (
            [d.strip() for d in devices_raw.replace(",", " ").split() if d.strip()]
            if devices_raw
            else None
        )
        categories = (
            [c.strip() for c in categories_raw.replace(",", " ").split() if c.strip()]
            if categories_raw
            else None
        )

        self.app.push_screen(
            AuditScreen(
                config_path=config_path,
                inventory_path=inventory_path,
                device_overrides=device_overrides,
                skip_jump=skip_jump,
                categories=categories,
                output_dir=output_dir,
                username=username,
                password=password,
            )
        )

    @on(Button.Pressed, "#btn-quit")
    def _on_quit(self) -> None:
        self.app.exit()


# ---------------------------------------------------------------------------
# Audit screen
# ---------------------------------------------------------------------------

class AuditScreen(Screen):
    """Live audit dashboard with statistics panel and scrollable log."""

    BINDINGS = [Binding("ctrl+q", "app.quit", "Quit")]

    def __init__(
        self,
        *,
        config_path: str,
        inventory_path: Optional[str],
        device_overrides: Optional[List[str]],
        skip_jump: bool,
        categories: Optional[List[str]],
        output_dir: Optional[str],
        username: str,
        password: str,
    ) -> None:
        super().__init__()
        self._config_path = config_path
        self._inventory_path = inventory_path
        self._device_overrides = device_overrides
        self._skip_jump = skip_jump
        self._categories = categories
        self._output_dir = output_dir
        self._username = username
        self._password = password

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="audit-body"):
            with Vertical(id="stats-pane"):
                yield Static("STATISTICS", id="stats-heading")
                yield Static("", classes="stat-item")
                yield Static("Devices:     –", id="stat-devices", classes="stat-item")
                yield Static("", classes="stat-item")
                yield Static("Completed:   0", id="stat-complete", classes="stat-item")
                yield Static("Compliant:   0", id="stat-pass",     classes="stat-item")
                yield Static("Failures:    0", id="stat-fail",     classes="stat-item")
                yield Static("Warnings:    0", id="stat-warn",     classes="stat-item")
                yield Static("Errors:      0", id="stat-err",      classes="stat-item")
            with Vertical(id="log-pane"):
                yield Static("LIVE LOG", id="log-heading")
                yield RichLog(id="audit-log", highlight=True, markup=True, wrap=True)
        with Horizontal(id="status-bar"):
            yield Static("● Initialising…", id="status-text")
        yield Footer()

    def on_mount(self) -> None:
        self._attach_tui_handler()
        self._run_audit()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _attach_tui_handler(self) -> None:
        """Replace console (stream) handlers with the TUI log handler."""
        root = logging.getLogger()
        root.handlers = [
            h for h in root.handlers
            if isinstance(h, logging.FileHandler)
            or not isinstance(h, logging.StreamHandler)
        ]
        tui_handler = TUILogHandler(self.app)
        tui_handler.setLevel(logging.DEBUG)
        root.addHandler(tui_handler)
        for name in _NOISY_LOGGERS:
            logging.getLogger(name).setLevel(logging.WARNING)

    def _set_status(self, msg: str) -> None:
        """Thread-safe status bar update."""
        def _update() -> None:
            try:
                self.query_one("#status-text", Static).update(msg)
            except Exception:
                pass
        self.app.call_from_thread(_update)

    def _update_stats(self, results: list) -> None:
        """Refresh the statistics panel from completed results."""
        def _update() -> None:
            try:
                completed = len(results)
                compliant = sum(1 for r in results if r.fail_count == 0)
                failures  = sum(1 for r in results if r.fail_count > 0)
                warnings  = sum(r.warn_count  for r in results)
                errors    = sum(r.error_count for r in results)
                self.query_one("#stat-complete", Static).update(f"Completed:   {completed}")
                self.query_one("#stat-pass",     Static).update(f"Compliant:   {compliant}")
                self.query_one("#stat-fail",     Static).update(f"Failures:    {failures}")
                self.query_one("#stat-warn",     Static).update(f"Warnings:    {warnings}")
                self.query_one("#stat-err",      Static).update(f"Errors:      {errors}")
            except Exception:
                pass
        self.app.call_from_thread(_update)

    # ── Audit worker ──────────────────────────────────────────────────────────

    @work(thread=True)
    def _run_audit(self) -> None:
        """Full audit pipeline — runs in a background thread."""
        from .auditor import load_device_inventory, run_audit

        try:
            # Inject credentials via env vars so CredentialHandler picks them up
            os.environ["SWITCH_USER"] = self._username
            os.environ["SWITCH_PASS"] = self._password

            self._set_status("● Loading device inventory…")
            log.info("TUI audit starting — config: %s", self._config_path)

            # Pre-fetch device count for the stats panel
            if self._device_overrides:
                device_count: int | str = len(self._device_overrides)
            else:
                try:
                    devices = load_device_inventory(
                        self._inventory_path, self._config_path
                    )
                    device_count = len(devices)
                except Exception:
                    device_count = "?"

            def _set_device_count() -> None:
                try:
                    self.query_one("#stat-devices", Static).update(
                        f"Devices:     {device_count}"
                    )
                except Exception:
                    pass

            self.app.call_from_thread(_set_device_count)

            self._set_status("● Running compliance audit…")
            results = run_audit(
                config_path=self._config_path,
                device_overrides=self._device_overrides,
                skip_jump=self._skip_jump,
                categories=self._categories,
                output_dir=self._output_dir,
                inventory_path=self._inventory_path,
            )

            self._update_stats(results)
            failures = sum(1 for r in results if r.fail_count > 0)
            self._set_status(
                f"✓ Complete — {len(results)} device(s) audited, "
                f"{failures} with compliance failures"
            )
            log.info(
                "Audit complete — %d device(s), %d with failures",
                len(results),
                failures,
            )

            def _show_complete() -> None:
                self.app.push_screen(CompleteScreen(results=results))

            self.app.call_from_thread(_show_complete)

        except Exception as exc:
            log.exception("Audit pipeline failed unexpectedly")
            self._set_status(f"✗ Error: {exc}")
        finally:
            os.environ.pop("SWITCH_USER", None)
            os.environ.pop("SWITCH_PASS", None)


# ---------------------------------------------------------------------------
# Complete screen
# ---------------------------------------------------------------------------

class CompleteScreen(Screen):
    """Summary screen shown after a successful audit run."""

    BINDINGS = [
        Binding("escape", "back_to_log", "Back to Log"),
        Binding("ctrl+q", "app.quit", "Quit"),
    ]

    def __init__(self, *, results: list) -> None:
        super().__init__()
        self._results = results

    def compose(self) -> ComposeResult:
        total       = len(self._results)
        compliant   = sum(1 for r in self._results if r.fail_count == 0)
        with_fails  = sum(1 for r in self._results if r.fail_count > 0)
        total_chks  = sum(r.total       for r in self._results)
        total_pass  = sum(r.pass_count  for r in self._results)
        total_fail  = sum(r.fail_count  for r in self._results)
        total_warn  = sum(r.warn_count  for r in self._results)
        total_err   = sum(r.error_count for r in self._results)

        yield Header(show_clock=True)
        with Container(id="complete-container"):
            yield Static("AUDIT COMPLETE", id="complete-title")
            yield Static(
                f"  Devices audited    : {total}",
                classes="result-row result-ok",
            )
            yield Static(
                f"  Fully compliant    : {compliant}",
                classes=f"result-row {'result-ok' if compliant == total else 'result-warn'}",
            )
            yield Static(
                f"  With failures      : {with_fails}",
                classes=f"result-row {'result-warn' if with_fails else 'result-ok'}",
            )
            yield Static(
                f"  Total checks       : {total_chks}",
                classes="result-row result-ok",
            )
            yield Static(
                f"  ✔ Pass             : {total_pass}",
                classes="result-row result-ok",
            )
            yield Static(
                f"  ✘ Fail             : {total_fail}",
                classes=f"result-row {'result-warn' if total_fail else 'result-ok'}",
            )
            yield Static(
                f"  ⚠ Warnings         : {total_warn}",
                classes=f"result-row {'result-warn' if total_warn else 'result-ok'}",
            )
            yield Static(
                f"  ✕ Errors           : {total_err}",
                classes=f"result-row {'result-warn' if total_err else 'result-ok'}",
            )
            with Horizontal(id="complete-btn-row"):
                yield Button("Back to Log", variant="default", id="btn-back")
                yield Button("Quit", variant="primary", id="btn-quit-final")
        yield Footer()

    @on(Button.Pressed, "#btn-back")
    def _back(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#btn-quit-final")
    def _quit(self) -> None:
        self.app.exit()

    def action_back_to_log(self) -> None:
        self.app.pop_screen()


# ---------------------------------------------------------------------------
# Application shell
# ---------------------------------------------------------------------------

class ComplianceAuditApp(App):
    """Textual application shell for Cisco Compliance Audit."""

    TITLE = "Cisco Compliance Audit"
    BINDINGS = [Binding("ctrl+q", "quit", "Quit")]

    CSS = """
    /* ─── Global ──────────────────────────────────────────────────────────── */

    Screen {
        background: $background;
    }

    /* ─── Setup screen ─────────────────────────────────────────────────────── */

    #setup-outer {
        width: 100%;
        height: 1fr;
        align: center top;
    }

    #setup-inner {
        width: 88;
        height: auto;
        border: round $primary;
        padding: 1 3;
        background: $surface;
    }

    #app-title {
        text-align: center;
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
        padding-bottom: 1;
        border-bottom: solid $primary;
    }

    .section-label {
        text-style: bold;
        color: $accent;
        margin-top: 1;
        margin-bottom: 0;
    }

    .field-label {
        color: $text-muted;
        margin-bottom: 0;
    }

    #btn-row {
        align: center middle;
        height: 3;
        margin-top: 1;
    }

    #btn-start {
        margin-right: 2;
    }

    /* ─── Audit screen ─────────────────────────────────────────────────────── */

    #audit-body {
        height: 1fr;
    }

    #stats-pane {
        width: 28;
        min-width: 24;
        border-right: solid $primary;
        padding: 1 2;
        background: $surface;
    }

    #stats-heading {
        text-align: center;
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
    }

    .stat-item {
        height: 1;
    }

    #log-pane {
        width: 1fr;
        padding: 0 1;
    }

    #log-heading {
        text-style: bold;
        color: $primary;
    }

    #status-bar {
        height: 3;
        border-top: solid $primary;
        background: $surface;
        padding: 0 2;
        align: left middle;
    }

    /* ─── Complete screen ──────────────────────────────────────────────────── */

    CompleteScreen {
        align: center middle;
    }

    #complete-container {
        width: 60;
        border: round $success;
        padding: 2 4;
        background: $surface;
    }

    #complete-title {
        text-align: center;
        text-style: bold;
        color: $success;
        margin-bottom: 1;
        padding-bottom: 1;
        border-bottom: solid $success;
    }

    .result-row {
        height: 1;
    }

    .result-ok {
        color: $success;
    }

    .result-warn {
        color: $warning;
    }

    #complete-btn-row {
        align: center middle;
        height: 3;
        margin-top: 1;
    }

    #btn-back {
        margin-right: 2;
    }
    """

    def on_mount(self) -> None:
        configure_logging()
        self.sub_title = f"v{get_version()}  ·  Cisco IOS-XE Compliance Auditor"
        self.push_screen(SetupScreen())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def launch_textual(parser: argparse.ArgumentParser) -> None:
    """Launch the full-screen Textual UI."""
    ComplianceAuditApp().run()
