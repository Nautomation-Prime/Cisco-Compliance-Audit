import getpass
import os
import logging
import sys
import win32cred
from .config_loader import Config

log = logging.getLogger(__name__)
cfg = Config("compliance_config.yaml")

class CredentialHandler:
    """
    Credential handler for network automation projects.

    Provides methods to retrieve credentials from environment variables,
    Windows Credential Manager, or interactive prompts. Also supports
    writing credentials back to Credential Manager.
    """

    def __init__(self, target: str | None = None) -> None:
        """
        Initialize the credential handler.

        Args:
            target: Credential target name (default from config or 'MyApp/ADM').
        """
        self.target = target or os.environ.get("CREDENTIAL_TARGET", cfg.cred_target or "MyApp/ADM")

    def get_secret_with_fallback(self) -> tuple[str, str]:
        """
        Try environment variables, then Windows Credential Manager, then interactive prompt.
        Environment variables checked (in order):
          - SWITCH_USER / SWITCH_PASS
          - CREDENTIAL_USER / CREDENTIAL_PASS
        """
        # 1) Environment overrides
        for user_env, pass_env in (("SWITCH_USER", "SWITCH_PASS"), ("CREDENTIAL_USER", "CREDENTIAL_PASS")):
            user = os.environ.get(user_env)
            pwd = os.environ.get(pass_env)
            if user and pwd:
                return user.strip(), pwd

        # 2) Windows Credential Manager (optional)
        try:
            cred = win32cred.CredRead(self.target, win32cred.CRED_TYPE_GENERIC)  # type: ignore
            user = cred.get("UserName")
            blob = cred.get("CredentialBlob")
            pwd = None
            if blob:
                # CredentialBlob is typically UTF-16LE for Windows generic creds
                try:
                    pwd = blob.decode("utf-16le")
                except Exception:
                    try:
                        pwd = blob.decode("utf-8", errors="ignore")
                    except Exception:
                        pwd = None
            if user and pwd:
                log.critical(f"Found stored Primary user: {user} (target: {self.target})")
                override = input("Press Enter to accept, or type a different username: ").strip()
                if override:
                    primary_user = override
                    primary_pass = getpass.getpass("Enter switch/jump password (Primary): ")
                    if self._prompt_yes_no(
                        f"Save these Primary creds to Credential Manager as '{self.target}'?", default_no=True
                    ):
                        self._write_win_cred(primary_user, primary_pass)
                    else:
                        primary_user, primary_pass = user, pwd
                    return primary_user, primary_pass
                return user, pwd

        except Exception:
            log.debug(f"Win32 credential read failed or not available for target {self.target}", exc_info=True)

        # 3) Interactive prompt
        user = input("Enter switch/jump username: ").strip()
        pwd = getpass.getpass("Enter switch/jump password: ")
        if self._prompt_yes_no(f"Save these Primary creds to Credential Manager as '{self.target}'?", default_no=True):
            self._write_win_cred(user, pwd)
        if not user or not pwd:
            raise RuntimeError(
                "Credentials not found in Windows Credential Manager, env vars, or provided interactively."
            )
        return user, pwd

    def _write_win_cred(self, username: str, password: str, persist: int = 2) -> bool:
        """
        Write or update a generic credential in Windows Credential Manager.

        Args:
            username: Username to store.
            password: Password to store.
            persist: Persistence (2 = local machine).

        Returns:
            True if the write succeeded, False otherwise.
        """
        try:
            if not sys.platform.startswith("win"):
                log.warning("Not a Windows platform; cannot store credentials in Credential Manager.")
                return False

            blob_bytes = password.encode("utf-16le")
            credential = {
                "Type": win32cred.CRED_TYPE_GENERIC,
                "TargetName": self.target,
                "UserName": username,
                "CredentialBlob": blob_bytes,
                "Comment": "Created by CDP Network Audit tool",
                "Persist": persist,
            }
            try:
                win32cred.CredWrite(credential, 0)
            except TypeError as te:
                log.debug(f"CredWrite rejected bytes for CredentialBlob ({te}). Retrying with unicode string.")
                credential["CredentialBlob"] = password
                win32cred.CredWrite(credential, 0)
            log.info(f"Stored/updated credentials in Windows Credential Manager: {self.target}")
            return True
        except Exception:
            log.exception(f"Failed to write credentials for '{self.target}'")
            return False

    def get_enable_secret(self) -> str | None:
        """
        Retrieve enable secret if USE_ENABLE is set in environment.
        """
        use_enable = os.environ.get("USE_ENABLE", "false").lower() in {"1", "true", "yes", "y"}
        if not use_enable:
            return None
        return os.environ.get("ENABLE_SECRET")

    @staticmethod
    def _prompt_yes_no(msg: str, default_no: bool = True) -> bool:
        """
        Simple interactive [y/N] or [Y/n] prompt.
        """
        suffix = " [y/N] " if default_no else " [Y/n] "
        ans = input(msg + suffix).strip().lower()
        if ans == "":
            return not default_no
        return ans in ("y", "yes")