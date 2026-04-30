"""Logging bootstrap for Cisco Compliance Audit."""

import logging
import logging.config
import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_LOGGING_CONF = _ROOT / "assets" / "config_files" / "logging.conf"


def configure_logging() -> None:
    """Configure logging using the INI file if available; otherwise fall back
    to a basic file + console setup.

    The LOGGING_CONFIG environment variable can override the default path.
    The logs/ directory is created automatically if it does not yet exist.
    """
    cfg_env = os.getenv("LOGGING_CONFIG", "").strip()
    cfg_path = Path(cfg_env) if cfg_env else _DEFAULT_LOGGING_CONF

    # Ensure logs/ exists before any FileHandler tries to open the file
    Path("logs").mkdir(exist_ok=True)

    if cfg_path.exists():
        logging.config.fileConfig(str(cfg_path), disable_existing_loggers=False)
        return

    # Fallback: basic dual-handler setup (console INFO, file DEBUG)
    root = logging.getLogger()
    if root.handlers:
        return  # Already configured — don't add duplicate handlers

    root.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s - %(levelname)-8s  %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(fmt)

    file_handler = logging.FileHandler("logs/debug.log", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)

    root.addHandler(console_handler)
    root.addHandler(file_handler)

    # Silence noisy third-party loggers in the file too
    for name in ("paramiko", "paramiko.transport", "netmiko.utilities"):
        logging.getLogger(name).setLevel(logging.WARNING)
