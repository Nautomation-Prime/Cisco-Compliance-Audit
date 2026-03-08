import logging
from netmiko import ConnectHandler
from netmiko.base_connection import BaseConnection
from typing import Any, Optional
from .jump_manager import JumpManager

log = logging.getLogger(__name__)


class DeviceConnector:
    """
    Lightweight wrapper around Netmiko.ConnectHandler.

    Encapsulates connection parameters and provides a method to establish
    a connection to a network device. Supports optional jump (JumpManager)
    which must provide a direct-tcpip channel via .open_channel().
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        device_type: str = "cisco_ios",
        jump: Optional[JumpManager] = None,
        port: int = 22,
        allow_agent: bool = False,
        look_for_keys: bool = False,
        **extras: Any,
    ) -> None:
        """
        Initialize the DeviceConnector with connection parameters.

        Args:
            ip: Device IP address.
            username: Login username.
            password: Login password.
            device_type: Netmiko device type (default 'cisco_ios').
            jump: Optional JumpManager for proxy/jump connections.
            port: SSH port (default 22).
            allow_agent: Whether to allow SSH agent.
            look_for_keys: Whether to look for SSH keys.
            extras: Additional keyword arguments passed to ConnectHandler.
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.device_type = device_type
        self.jump = jump
        self.port = port
        self.allow_agent = allow_agent
        self.look_for_keys = look_for_keys
        self.extras = extras

    def connect(self) -> BaseConnection:
        """
        Establish a connection to the device using Netmiko.ConnectHandler.

        Returns:
            BaseConnection: Active Netmiko connection object.

        Raises:
            Exception: If connection fails or jump channel cannot be opened.
        """
        kwargs: dict[str, Any] = {
            "device_type": self.device_type,
            "host": self.ip,
            "username": self.username,
            "password": self.password,
            "port": self.port,
            "allow_agent": self.allow_agent,
            "look_for_keys": self.look_for_keys,
            "auth_timeout": 20,
            "banner_timeout": 30,
            "conn_timeout": 25,
            "fast_cli": False,
        }
        kwargs.update(self.extras)

        # Handle optional jump manager
        if self.jump:
            try:
                sock = self.jump.open_channel(self.ip, self.port)
                kwargs["sock"] = sock
                log.debug(f"Opened jump channel to {self.ip}:{self.port}")
            except Exception:
                log.exception(f"Failed to open jump channel to {self.ip}:{self.port}")
                raise

        # Remove unsupported kwargs for some BaseConnection variants
        for _k in ("look_for_keys", "allow_agent"):
            if _k in kwargs:
                log.debug(f"Removing unsupported kwarg {_k} before ConnectHandler()")
                kwargs.pop(_k)

        log.debug(f"Connecting to device {self.ip} ({self.device_type})")
        try:
            return ConnectHandler(**kwargs)
        except Exception:
            log.exception(f"ConnectHandler failed for {self.ip}")
            raise