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

    @staticmethod
    def _normalise_device_entry(entry, *, location: str = "devices") -> dict:
        """Turn a bare string or dict into a normalised ``{hostname, ip}`` dict."""
        if isinstance(entry, str):
            value = entry.strip()
            if not value:
                raise ValueError(
                    f"Empty string in {location} — each entry must be a "
                    "hostname, IP address, or {{hostname: …, ip: …}} mapping."
                )
            parts = value.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return {"ip": value, "hostname": value}
            return {"hostname": value, "ip": value}
        if isinstance(entry, dict):
            out = dict(entry)
            if "hostname" not in out and "ip" not in out:
                raise ValueError(
                    f"Device entry in {location} must contain at least "
                    f"'hostname' or 'ip': {entry!r}"
                )
            if "hostname" in out and "ip" not in out:
                out["ip"] = out["hostname"]
            elif "ip" in out and "hostname" not in out:
                out["hostname"] = out["ip"]
            return out
        raise ValueError(
            f"Invalid entry in {location} (expected string or mapping, "
            f"got {type(entry).__name__}): {entry!r}"
        )

    @classmethod
    def _flatten_inventory(cls, data: dict) -> list:
        """Merge flat ``devices:`` list and Ansible-style ``groups:``."""
        flat: list = []
        errors: list = []

        for idx, raw in enumerate(data.get("devices", []) or []):
            try:
                flat.append(
                    cls._normalise_device_entry(raw, location=f"devices[{idx}]")
                )
            except ValueError as exc:
                errors.append(str(exc))

        for group_name, group_body in (data.get("groups") or {}).items():
            if not isinstance(group_body, dict):
                errors.append(
                    f"Group '{group_name}' is not a mapping — expected "
                    "keys like 'role' and 'devices'."
                )
                continue
            group_role = group_body.get("role")
            for idx, raw in enumerate(group_body.get("devices") or []):
                try:
                    entry = cls._normalise_device_entry(
                        raw, location=f"groups.{group_name}.devices[{idx}]"
                    )
                except ValueError as exc:
                    errors.append(str(exc))
                    continue
                if group_role and "role" not in entry:
                    entry["role"] = group_role
                entry.setdefault("_group", group_name)
                flat.append(entry)

        if errors:
            raise ValueError(
                "Inventory validation failed:\n  • " + "\n  • ".join(errors)
            )

        seen: dict = {}
        unique: list = []
        for entry in flat:
            ip = entry["ip"]
            source = entry.get("_group", "devices")
            if ip in seen:
                continue
            seen[ip] = source
            unique.append(entry)
        return unique

    @property
    def devices(self) -> list:
        """Load devices from the separate inventory file.

        Supports both a flat ``devices:`` list and Ansible-style ``groups:``.
        """
        inv_file = self._config.get("inventory_file", "devices.yaml")
        inv_path = self._config_file.parent / inv_file
        if not inv_path.exists():
            # Fallback: check for inline devices (backwards compat)
            return self._flatten_inventory(self._config)
        with open(inv_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return self._flatten_inventory(data)

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
