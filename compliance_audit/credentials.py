import getpass
import os
import logging

log = logging.getLogger(__name__)

class CredentialHandler:
    """
    Credential handler for network automation projects.

    Provides methods to retrieve credentials from environment variables
    or interactive prompts.
    """

    def __init__(self, target: str | None = None) -> None:
        """
        Initialize the credential handler.

        Args:
            target: Unused parameter, kept for backward compatibility.
        """
        # target parameter is kept for backward compatibility but no longer used
        pass

    def get_secret_with_fallback(self) -> tuple[str, str]:
        """
        Try environment variables, then interactive prompt.
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

        # 2) Interactive prompt
        user = input("Enter switch/jump username: ").strip()
        pwd = getpass.getpass("Enter switch/jump password: ")
        if not user or not pwd:
            raise RuntimeError(
                "Credentials not found in env vars or provided interactively."
            )
        return user, pwd

    def get_enable_secret(self) -> str | None:
        """
        Retrieve enable secret if USE_ENABLE is set in environment.
        """
        use_enable = os.environ.get("USE_ENABLE", "false").lower() in {"1", "true", "yes", "y"}
        if not use_enable:
            return None
        return os.environ.get("ENABLE_SECRET")