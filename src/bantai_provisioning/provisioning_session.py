#!/usr/bin/env python3

"""BANTAI provisioning session manager for hotspot credentials."""

import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from bantai_provisioning.security import ProvisioningHandshake


class HotspotConfig:
    """Manages hotspot credential storage and network configuration."""

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.credentials_file = config_dir / "hotspot_credentials.json"

    def save_credentials(self, ssid: str, password: str) -> bool:
        """Save hotspot credentials for the Pi to connect to."""
        try:
            credentials = {
                "ssid": ssid,
                "password": password,
                "timestamp": time.time(),
                "connected": False,
            }

            # Write with restricted permissions
            self.credentials_file.write_text(json.dumps(credentials, indent=2))
            self.credentials_file.chmod(0o600)

            return True
        except Exception as e:
            print(f"[BANTAI] Failed to save credentials: {e}")
            return False

    def mark_connected(self) -> None:
        """Mark the hotspot connection as successful."""
        if self.credentials_file.exists():
            data = json.loads(self.credentials_file.read_text())
            data["connected"] = True
            data["connected_at"] = time.time()
            self.credentials_file.write_text(json.dumps(data, indent=2))

    def get_credentials(self) -> Optional[dict]:
        """Load saved credentials if they exist."""
        if self.credentials_file.exists():
            return json.loads(self.credentials_file.read_text())
        return None

    def clear_credentials(self) -> None:
        """Remove stored credentials."""
        self.credentials_file.unlink(missing_ok=True)


class ProvisioningSession:
    """Manages a complete provisioning session with the Flutter app."""

    def __init__(
        self,
        handshake: ProvisioningHandshake,
        hotspot_config: HotspotConfig,
    ):
        self.handshake = handshake
        self.hotspot_config = hotspot_config
        self._connected_to_hotspot = False

    def process_message(self, message: bytes) -> Optional[bytes]:
        """Process an incoming message and return a response if needed.

        Returns None if no response is required.
        """
        try:
            # First, check if this is a handshake message
            data = json.loads(message.decode("utf-8"))
            msg_type = data.get("type")

            if msg_type == "client_hello":
                return self.handshake.handle_client_hello(message)

            if msg_type == "authorize":
                success = self.handshake.handle_authorization(message)
                if success:
                    return json.dumps({
                        "type": "authorization_success",
                        "device_id": self.handshake.device_id,
                    }).encode("utf-8")
                return json.dumps({
                    "type": "authorization_failed",
                    "error": "Invalid setup token",
                }).encode("utf-8")

            # After authorization, decrypt and handle provisioning messages
            if not self.handshake.authorized:
                return json.dumps({
                    "type": "error",
                    "error": "Session not authorized",
                }).encode("utf-8")

            payload = self.handshake.decrypt_client_message(message)
            return self._handle_provisioning_payload(payload)

        except Exception as e:
            return json.dumps({
                "type": "error",
                "error": str(e),
            }).encode("utf-8")

    def _handle_provisioning_payload(self, payload: dict) -> Optional[bytes]:
        """Handle decrypted provisioning messages."""
        msg_type = payload.get("type")

        if msg_type == "hotspot_credentials":
            return self._handle_hotspot_credentials(payload)

        if msg_type == "ping":
            return self.handshake.encrypt_server_message({
                "type": "pong",
                "timestamp": time.time(),
            })

        return self.handshake.encrypt_server_message({
            "type": "error",
            "error": f"Unknown message type: {msg_type}",
        })

    def _handle_hotspot_credentials(self, payload: dict) -> bytes:
        """Process hotspot credentials and attempt connection."""
        ssid = payload.get("ssid")
        password = payload.get("password")

        if not ssid or not password:
            return self.handshake.encrypt_server_message({
                "type": "hotspot_response",
                "success": False,
                "error": "Missing SSID or password",
            })

        # Save credentials
        if not self.hotspot_config.save_credentials(ssid, password):
            return self.handshake.encrypt_server_message({
                "type": "hotspot_response",
                "success": False,
                "error": "Failed to save credentials",
            })

        # Attempt to connect to the hotspot
        success = self._connect_to_hotspot(ssid, password)

        if success:
            self._connected_to_hotspot = True
            self.hotspot_config.mark_connected()

            return self.handshake.encrypt_server_message({
                "type": "hotspot_response",
                "success": True,
                "ssid": ssid,
                "message": "Connected to hotspot successfully",
            })

        return self.handshake.encrypt_server_message({
            "type": "hotspot_response",
            "success": False,
            "error": "Failed to connect to hotspot",
        })

    def _connect_to_hotspot(self, ssid: str, password: str) -> bool:
        """Attempt to connect to the phone's hotspot.

        This uses nmcli (NetworkManager CLI) to configure the connection.
        """
        try:
            # Check if NetworkManager is available
            result = subprocess.run(
                ["nmcli", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                print("[BANTAI] NetworkManager not available")
                return False

            # Create or update the hotspot connection
            connection_name = f"bantai-hotspot-{ssid}"

            # First, try to delete any existing connection with this name
            subprocess.run(
                ["nmcli", "connection", "delete", connection_name],
                capture_output=True,
                timeout=10,
            )

            # Create a new connection profile
            result = subprocess.run(
                [
                    "nmcli", "device", "wifi", "connect",
                    ssid,
                    "password", password,
                    "name", connection_name,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                print(f"[BANTAI] Connected to hotspot: {ssid}")
                return True

            print(f"[BANTAI] Failed to connect: {result.stderr}")
            return False

        except subprocess.TimeoutExpired:
            print("[BANTAI] Connection attempt timed out")
            return False
        except Exception as e:
            print(f"[BANTAI] Connection error: {e}")
            return False

    @property
    def is_connected_to_hotspot(self) -> bool:
        return self._connected_to_hotspot

    @property
    def is_authorized(self) -> bool:
        return self.handshake.authorized
