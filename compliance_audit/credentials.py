import getpass
import os
import logging
from functools import lru_cache
from pathlib import Path

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# .env file loader
# ---------------------------------------------------------------------------

_RECOGNISED_ENV_VARS = frozenset({
    "SWITCH_USER", "SWITCH_PASS",
    "CREDENTIAL_USER", "CREDENTIAL_PASS",
    "ENABLE_SECRET", "USE_ENABLE",
})

_dotenv_loaded = False


def load_dotenv() -> None:
    """Load a .env file from the project root or CWD into os.environ.

    Only variables in ``_RECOGNISED_ENV_VARS`` are accepted.  Variables that
    are already set in the environment are never overwritten, so real
    environment variables always take precedence over the file.

    The function is idempotent — subsequent calls are no-ops.
    """
    global _dotenv_loaded
    if _dotenv_loaded:
        return
    _dotenv_loaded = True

    # Search order: project root (next to run.bat/run.sh) then CWD
    candidates = [
        Path(__file__).resolve().parent.parent / ".env",
        Path.cwd() / ".env",
    ]

    env_path: Path | None = None
    for p in candidates:
        if p.is_file():
            env_path = p
            break

    if env_path is None:
        return

    loaded: list[str] = []
    try:
        with open(env_path, encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                # Skip blank lines and comments
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                # Strip optional surrounding quotes from value
                value = value.strip().strip('"').strip("'")
                if key not in _RECOGNISED_ENV_VARS:
                    continue
                if os.environ.get(key):
                    continue  # Real env var already set — don't overwrite
                os.environ[key] = value
                loaded.append(key)
    except OSError as exc:
        log.debug("Could not read .env file %s: %s", env_path, exc)
        return

    if loaded:
        log.debug(".env loaded from %s — set: %s", env_path, ", ".join(loaded))

# keyring is an optional dependency — import lazily so the tool still
# works when it isn't installed and credential_store is "none".
@lru_cache(maxsize=1)
def _get_keyring():
    """Lazy-import keyring so we fail late, not at module load."""
    try:
        import keyring
    except ImportError as exc:
        raise RuntimeError(
            'credential_store is set to "keyring" but the keyring '
            "package is not installed.  Install it with:\n"
            "  pip install keyring"
        ) from exc
    return keyring


class CredentialHandler:
    """
    Credential handler for network automation projects.

    Lookup order (each step falls through to the next):
      1. OS keyring         — if credential_store == "keyring"
      2. Environment vars   — SWITCH_USER/SWITCH_PASS or CREDENTIAL_USER/CREDENTIAL_PASS
      3. Interactive prompt  — asks the user at the terminal

    When the keyring backend is enabled, credentials obtained from
    env-vars or the interactive prompt are automatically saved back
    to the keyring so subsequent runs are hands-free.
    """

    _USER_SUFFIX = "/username"
    _PASS_SUFFIX = "/password"

    def __init__(
        self,
        credential_store: str = "none",
        keyring_service: str = "cisco-compliance-audit",
    ) -> None:
        self._store = credential_store.lower().strip()
        self._service = keyring_service

    # ── public API ────────────────────────────────────────────

    def get_secret_with_fallback(self) -> tuple[str, str]:
        """
        Return (username, password) using the configured lookup chain.
        """
        # 0) Load .env file if present (real env vars take precedence)
        load_dotenv()

        # 1) Keyring
        if self._store == "keyring":
            creds = self._from_keyring()
            if creds:
                log.info("Credentials loaded from OS keyring (%s)", self._service)
                return creds

        # 2) Environment overrides
        for user_env, pass_env in (
            ("SWITCH_USER", "SWITCH_PASS"),
            ("CREDENTIAL_USER", "CREDENTIAL_PASS"),
        ):
            user = os.environ.get(user_env)
            pwd = os.environ.get(pass_env)
            if user and pwd:
                self._maybe_store(user.strip(), pwd)
                return user.strip(), pwd

        # 3) Interactive prompt
        user = input("Enter switch/jump username: ").strip()
        pwd = getpass.getpass("Enter switch/jump password: ")
        if not user or not pwd:
            raise RuntimeError(
                "Credentials not found in keyring, env vars, or provided interactively."
            )
        self._maybe_store(user, pwd)
        return user, pwd

    def get_enable_secret(self) -> str | None:
        """
        Retrieve enable secret if USE_ENABLE is set in environment.
        """
        load_dotenv()
        use_enable = os.environ.get("USE_ENABLE", "false").lower() in {
            "1",
            "true",
            "yes",
            "y",
        }
        if not use_enable:
            return None

        # Try keyring first, then env var
        if self._store == "keyring":
            kr = _get_keyring()
            secret = kr.get_password(self._service, "enable_secret")
            if secret:
                return secret

        return os.environ.get("ENABLE_SECRET")

    # ── private helpers ───────────────────────────────────────

    def _from_keyring(self) -> tuple[str, str] | None:
        """Try to load username + password from the OS keyring."""
        kr = _get_keyring()
        user = kr.get_password(self._service, self._USER_SUFFIX)
        pwd = kr.get_password(self._service, self._PASS_SUFFIX)
        if user and pwd:
            return user, pwd
        return None

    def _maybe_store(self, username: str, password: str) -> None:
        """If keyring is enabled, persist the credentials we just obtained."""
        if self._store != "keyring":
            return
        kr = _get_keyring()
        kr.set_password(self._service, self._USER_SUFFIX, username)
        kr.set_password(self._service, self._PASS_SUFFIX, password)
        log.info("Credentials saved to OS keyring (%s)", self._service)
