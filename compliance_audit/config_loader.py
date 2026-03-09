import os
import yaml
from pathlib import Path

class Config:
    """
    Canonical configuration loader.
    - Loads structured parameters from YAML.
    - Pulls sensitive values from environment variables.
    - Also exposes compliance-audit sections when loaded from the
      compliance_config.yaml.
    """

    def __init__(self, config_file: str = "compliance_config.yaml"):
        self._config_file = Path(config_file)
        if not self._config_file.exists():
            # Try relative to this module's directory
            self._config_file = Path(__file__).parent / config_file
        self._config = self._load_yaml()

        # Example: environment variables for secrets
        self._env = {
            "API_TOKEN": os.getenv("API_TOKEN"),
        }

    def _load_yaml(self) -> dict:
        if not self._config_file.exists():
            raise FileNotFoundError(f"Config file not found: {self._config_file}")
        with open(self._config_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    # --- Public API surface ---
    @property
    def jump_host(self) -> str:
        conn = self._config.get("connection", {})
        return conn.get("jump_host") or self._config.get("JUMP_HOST", "")

    @property
    def settings(self) -> dict:
        return self._config.get("settings", {})

    @property
    def connection(self) -> dict:
        return self._config.get("connection", {})

    @property
    def devices(self) -> list:
        return self._config.get("devices", [])

    @property
    def audit_settings(self) -> dict:
        return self._config.get("audit_settings", {})

    @property
    def compliance(self) -> dict:
        return self._config.get("compliance", {})

    @property
    def raw(self) -> dict:
        return self._config

    def __repr__(self):
        return f"<Config file={self._config_file} keys={list(self._config.keys())}>"