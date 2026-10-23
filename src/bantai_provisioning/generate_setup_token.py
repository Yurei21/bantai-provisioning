#!/usr/bin/env python3

"""Generate a one-time setup token and QR code for BANTAI provisioning."""

import argparse
import secrets
import time
from pathlib import Path

import qrcode


def main():
    parser = argparse.ArgumentParser(
        description="Generate BANTAI provisioning setup token"
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path.home() / ".local/state/bantai-provisioning",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output file for the setup token (default: stdout)",
    )
    args = parser.parse_args()

    args.state_dir.mkdir(parents=True, exist_ok=True)
    args.state_dir.chmod(0o700)

    token_file = args.state_dir / "setup_token.txt"

    # Check if there's an existing unexpired token
    if token_file.exists():
        existing_token = token_file.read_text().strip()
        if existing_token:
            token_path = args.state_dir / "setup_token_meta.json"
            if token_path.exists():
                import json
                meta = json.loads(token_path.read_text())
                created_at = meta.get("created_at", 0)
                # Tokens are valid for 24 hours
                if time.time() - created_at < 86400:
                    print(f"Existing setup token (valid for {int((86400 - (time.time() - created_at)) / 3600)} more hours):")
                    print(f"\n  {existing_token}\n")
                    print("Display this token on the phone app to complete provisioning.")
                    return

    # Generate a new token
    token = secrets.token_urlsafe(32)

    # Save the token with restricted permissions
    token_file.write_text(token)
    token_file.chmod(0o600)

    # Save metadata
    import json
    meta = {
        "created_at": time.time(),
        "token_hash": secrets.token_hex(16),  # For display purposes only
    }
    meta_file = args.state_dir / "setup_token_meta.json"
    meta_file.write_text(json.dumps(meta, indent=2))
    meta_file.chmod(0o600)

    # Generate a QR code for the token (for convenience)
    qr_path = args.state_dir / "setup_token_qr.png"
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(token)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    image.save(qr_path)

    print("Generated new setup token:")
    print(f"\n  {token}\n")
    print(f"QR code saved to: {qr_path}")
    print("\nDisplay this token on the phone app to complete provisioning.")
    print("The token is valid for 24 hours.")


if __name__ == "__main__":
    main()
