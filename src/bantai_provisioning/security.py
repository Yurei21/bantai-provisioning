"""Authenticated cryptographic handshake for BANTAI BLE provisioning."""

import base64
import hashlib
import hmac
import json
import secrets
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL_PREFIX = b"BANTAI-PROVISION-v1\x00"
HKDF_INFO = b"BANTAI BLE provisioning session v1"
MAX_MESSAGE_SIZE = 4096
HANDSHAKE_TIMEOUT_SECONDS = 120


def encode64(data: bytes) -> str:
    """Encode bytes as URL-safe Base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode64(value: str, expected_length: int | None = None) -> bytes:
    """Decode URL-safe Base64 and optionally validate the result length."""
    if not isinstance(value, str) or not value:
        raise ValueError("Expected a non-empty Base64 string")

    if len(value) > MAX_MESSAGE_SIZE * 2:
        raise ValueError("Encoded value is too large")

    padding = "=" * (-len(value) % 4)
    decoded = base64.b64decode(
        value + padding,
        altchars=b"-_",
        validate=True,
    )

    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError("Unexpected decoded length")

    return decoded


def canonical_json(data: dict) -> bytes:
    """Serialize JSON deterministically for signing and key derivation."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def raw_public_key(key) -> bytes:
    """Return a public key in raw byte format."""
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def derive_session_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """Derive a 256-bit AES session key using HKDF-SHA256."""
    transcript_hash = hashlib.sha256(transcript).digest()

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript_hash,
        info=HKDF_INFO,
    ).derive(shared_secret)


class ProvisioningHandshake:
    """Server side of the BANTAI authenticated BLE setup handshake."""

    def reset_if_unauthorized(self) -> None:
    if not self.authorized and not self._token_consumed:
        self._session_key = None
        self._transcript_hash = None
        self._deadline = None
        self._seen_client_nonces.clear()

    def __init__(
        self,
        device_id: str,
        identity_key: Ed25519PrivateKey,
        setup_token: str,
    ):
        if not device_id or not setup_token:
            raise ValueError("Device ID and setup token are required")

        self.device_id = device_id
        self.identity_key = identity_key

        # Store only a digest of the one-time setup token.
        self._setup_token_hash = hashlib.sha256(
            setup_token.encode("utf-8")
        ).digest()

        self.authorized = False
        self._token_consumed = False
        self._session_key = None
        self._transcript_hash = None
        self._deadline = None
        self._seen_client_nonces: set[bytes] = set()

    def handle_client_hello(self, message: bytes) -> bytes:
        """Validate a client hello and return the signed server hello."""
        if self.authorized or self._token_consumed:
            raise ValueError("Provisioning session is already closed")

        if self._session_key is not None:
            raise ValueError("Handshake has already started")

        if not isinstance(message, bytes) or len(message) > MAX_MESSAGE_SIZE:
            raise ValueError("Invalid or oversized client hello")

        try:
            hello = json.loads(message.decode("utf-8"))
            if hello.get("type") != "client_hello":
                raise ValueError("Unexpected handshake message")

            client_public_bytes = decode64(
                hello["client_ephemeral"], 32
            )
            client_nonce = decode64(hello["client_nonce"], 32)

        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            raise ValueError("Malformed client hello") from None

        client_public = X25519PublicKey.from_public_bytes(
            client_public_bytes
        )

        # Generate a fresh ephemeral key pair and nonce for this session.
        server_ephemeral = X25519PrivateKey.generate()
        server_public_bytes = raw_public_key(server_ephemeral)
        server_nonce = secrets.token_bytes(32)

        identity_public_bytes = raw_public_key(self.identity_key)

        transcript_data = {
            "version": 1,
            "device_id": self.device_id,
            "identity_public": encode64(identity_public_bytes),
            "client_ephemeral": encode64(client_public_bytes),
            "client_nonce": encode64(client_nonce),
            "server_ephemeral": encode64(server_public_bytes),
            "server_nonce": encode64(server_nonce),
        }

        transcript = canonical_json(transcript_data)
        transcript_hash = hashlib.sha256(transcript).digest()

        signature = self.identity_key.sign(
            PROTOCOL_PREFIX + transcript
        )

        shared_secret = server_ephemeral.exchange(client_public)
        self._session_key = derive_session_key(
            shared_secret,
            transcript,
        )
        self._transcript_hash = transcript_hash
        self._deadline = time.monotonic() + HANDSHAKE_TIMEOUT_SECONDS

        response = {
            "type": "server_hello",
            "server_ephemeral": encode64(server_public_bytes),
            "server_nonce": encode64(server_nonce),
            "signature": encode64(signature),
            "transcript_hash": encode64(transcript_hash),
        }

        return canonical_json(response)

    def handle_authorization(self, message: bytes) -> bool:
        """Decrypt and validate the one-time setup-token authorization."""
        if (
            self.authorized
            or self._token_consumed
            or self._session_key is None
            or self._transcript_hash is None
        ):
            return False

        if time.monotonic() > self._deadline:
            self._close_session()
            return False

        if not isinstance(message, bytes) or len(message) > MAX_MESSAGE_SIZE:
            return False

        try:
            authorization = json.loads(message.decode("utf-8"))

            if authorization.get("type") != "authorize":
                return False

            nonce = decode64(authorization["nonce"], 12)
            ciphertext = decode64(authorization["ciphertext"])

            plaintext = AESGCM(self._session_key).decrypt(
                nonce,
                ciphertext,
                self._transcript_hash,
            )

            payload = json.loads(plaintext.decode("utf-8"))
            supplied_token = payload["setup_token"]

            if not isinstance(supplied_token, str):
                return False

            supplied_hash = hashlib.sha256(
                supplied_token.encode("utf-8")
            ).digest()

            if not hmac.compare_digest(
                supplied_hash,
                self._setup_token_hash,
            ):
                return False

        except (
            InvalidTag,
            ValueError,
            TypeError,
            KeyError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return False

        # Accept the token once, but retain the session for provisioning.
        self.authorized = True
        self._token_consumed = True
        self._setup_token_hash = b""

        return True


    def decrypt_client_message(self, message: bytes) -> dict:
        """Decrypt an authenticated client message after authorization."""
        if not self.authorized or self._session_key is None:
            raise ValueError("Provisioning session is not authorized")

        if self._deadline is None or time.monotonic() > self._deadline:
            self._close_session()
            raise ValueError("Provisioning session expired")

        if not isinstance(message, bytes) or len(message) > MAX_MESSAGE_SIZE:
            raise ValueError("Invalid or oversized message")

        try:
            envelope = json.loads(message.decode("utf-8"))

            if envelope.get("type") != "encrypted":
                raise ValueError("Unexpected message type")

            nonce = decode64(envelope["nonce"], 12)
            ciphertext = decode64(envelope["ciphertext"])

            if nonce in self._seen_client_nonces:
                raise ValueError("Replayed message")

            plaintext = AESGCM(self._session_key).decrypt(
                nonce,
                ciphertext,
                self._transcript_hash + b"client-to-server",
            )

            payload = json.loads(plaintext.decode("utf-8"))

            if not isinstance(payload, dict):
                raise ValueError("Expected a JSON object")

        except InvalidTag:
            raise ValueError("Message authentication failed") from None
        except (
            ValueError,
            TypeError,
            KeyError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            raise ValueError("Malformed encrypted message") from None

        self._seen_client_nonces.add(nonce)
        return payload

    def encrypt_server_message(self, payload: dict) -> bytes:
        """Encrypt an authenticated response for the provisioning client."""
        if not self.authorized or self._session_key is None:
            raise ValueError("Provisioning session is not authorized")

        if self._deadline is None or time.monotonic() > self._deadline:
            self._close_session()
            raise ValueError("Provisioning session expired")

        nonce = secrets.token_bytes(12)

        ciphertext = AESGCM(self._session_key).encrypt(
            nonce,
            canonical_json(payload),
            self._transcript_hash + b"server-to-client",
        )

        return canonical_json({
            "type": "encrypted",
            "nonce": encode64(nonce),
            "ciphertext": encode64(ciphertext),
        })

    def _close_session(self) -> None:
        """Discard ephemeral session material."""
        self._session_key = None
        self._transcript_hash = None
        self._deadline = None
        self._seen_client_nonces.clear()
        self.authorized = False
