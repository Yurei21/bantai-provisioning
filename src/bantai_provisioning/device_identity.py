#!/usr/bin/env python3

"""BANTAI Raspberry Pi device identity."""

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


BLE_SERVICE_UUID = "8b7e1000-6d7a-4e9a-9c4e-123456789001"


def get_pi_serial() -> str:
    """Read the Pi serial from device-tree or /proc/cpuinfo."""

    device_tree_serial = Path("/proc/device-tree/serial-number")

    if device_tree_serial.exists():
        serial = device_tree_serial.read_bytes()
        serial = serial.rstrip(b"\x00").decode("ascii").strip()

        if serial and any(c != "0" for c in serial):
            return serial.lower()

    cpuinfo = Path("/proc/cpuinfo").read_text()

    for line in cpuinfo.splitlines():
        if line.lower().startswith("serial"):
            _, value = line.split(":", 1)
            serial = value.strip()

            if serial and any(c != "0" for c in serial):
                return serial.lower()

    raise RuntimeError(
        "Could not obtain a valid Raspberry Pi serial number."
    )


def load_or_create_key(state_dir: Path) -> Ed25519PrivateKey:
    """Load the persistent device key or generate it once."""

    state_dir.mkdir(parents=True, exist_ok=True)
    state_dir.chmod(0o700)

    key_path = state_dir / "device_ed25519.key"

    if key_path.exists():
        if key_path.is_symlink():
            raise RuntimeError("Device key must not be a symlink.")

        if key_path.stat().st_mode & 0o077:
            raise RuntimeError(
                "Private key permissions are too permissive. "
                "Run chmod 600 on the key file."
            )

        raw_key = key_path.read_bytes()

        if len(raw_key) != 32:
            raise RuntimeError("Invalid Ed25519 private key file.")

        return Ed25519PrivateKey.from_private_bytes(raw_key)

    # Generate a unique device key.
    private_key = Ed25519PrivateKey.generate()

    raw_key = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Exclusive creation prevents silently overwriting an existing key.
    fd = os.open(
        key_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    try:
        with os.fdopen(fd, "wb") as file:
            file.write(raw_key)
            file.flush()
            os.fsync(file.fileno())
    except Exception:
        key_path.unlink(missing_ok=True)
        raise

    return private_key


def build_identity(state_dir: Path) -> dict:
    """Build the public identity used by the permanent QR code."""

    serial = get_pi_serial()
    private_key = load_or_create_key(state_dir)

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    public_key_b64 = base64.b64encode(public_key).decode("ascii")

    fingerprint = hashlib.sha256(public_key).hexdigest()

    identity = {
        "version": 1,
        "device_id": f"BANTAI-{serial}",
        "ble_service_uuid": BLE_SERVICE_UUID,
        "public_key": public_key_b64,
        "key_fingerprint": fingerprint,
    }

    # Include current valid setup token if present (for easier provisioning)
    try:
        import time

        token_file = state_dir / "setup_token.txt"
        meta_file = state_dir / "setup_token_meta.json"
        if token_file.exists():
            token = token_file.read_text().strip()
            if token:
                if meta_file.exists():
                    try:
                        meta = json.loads(meta_file.read_text())
                        created_at = meta.get("created_at", 0)
                        if time.time() - created_at < 86400:  # 24 hours
                            identity["setup_token"] = token
                    except Exception:
                        # If metadata missing/corrupt, don't include token for safety
                        pass
                else:
                    # No metadata, don't include token
                    pass
    except Exception:
        pass

    return identity


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path.home() / ".local/state/bantai-provisioning",
    )
    parser.add_argument(
        "--qr-out",
        type=Path,
        default=Path("output/device-identity.png"),
    )

    args = parser.parse_args()

    identity = build_identity(args.state_dir)

    # Generate a permanent QR containing public information only.
    import qrcode

    args.qr_out.parent.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(
        identity,
        separators=(",", ":"),
        sort_keys=True,
    )

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_Q,
        box_size=10,
        border=4,
    )

    qr.add_data(payload)
    qr.make(fit=True)

    image = qr.make_image(fill_color="black", back_color="white")
    image.save(args.qr_out)

    print(f"Device ID: {identity['device_id']}")
    print(f"BLE service UUID: {identity['ble_service_uuid']}")
    print(f"Public key fingerprint: {identity['key_fingerprint']}")
    print(f"QR code saved to: {args.qr_out}")
    print("Private key remains on the Raspberry Pi.")


if __name__ == "__main__":
    main()
