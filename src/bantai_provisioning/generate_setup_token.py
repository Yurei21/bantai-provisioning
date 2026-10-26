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
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force generate a new token even if one exists",
    )
    args = parser.parse_args()

    args.state_dir.mkdir(parents=True, exist_ok=True)
    args.state_dir.chmod(0o700)

    token_file = args.state_dir / "setup_token.txt"
    qr_path = args.state_dir / "setup_token_qr.png"

    # If token exists and not forced, reuse it (permanent token)
    if token_file.exists() and not args.force:
        existing_token = token_file.read_text().strip()
        if existing_token:
            print("Using existing permanent setup token:")
            print(f"\n  {existing_token}\n")
            print(f"QR code saved to: {qr_path}")
            # Regenerate QR in case it's missing
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=4,
            )
            qr.add_data(existing_token)
            qr.make(fit=True)
            image = qr.make_image(fill_color="black", back_color="white")
            image.save(qr_path)
            return

    # Generate a new permanent token
    token = secrets.token_urlsafe(32)

    # Save the token with restricted permissions
    token_file.write_text(token)
    token_file.chmod(0o600)

    # Save metadata (kept for compatibility)
    import json
    meta = {
        "created_at": time.time(),
        "permanent": True,
    }
    meta_file = args.state_dir / "setup_token_meta.json"
    meta_file.write_text(json.dumps(meta, indent=2))
    meta_file.chmod(0o600)

    # Generate a QR code for the token
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

    print("Generated permanent setup token:")
    print(f"\n  {token}\n")
    print(f"QR code saved to: {qr_path}")
    print("\nThis token will not expire. Print the combined QR for provisioning.")


if __name__ == "__main__":
    main()
