
import hashlib
import json
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from bantai_provisioning.security import (
    HKDF_INFO,
    PROTOCOL_PREFIX,
    ProvisioningHandshake,
    canonical_json,
    decode64,
    derive_session_key,
    encode64,
)


def raw_public_key(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_successful_handshake():
    print("Testing authenticated handshake...")

    # Simulate the Pi's long-term identity.
    pi_identity_key = Ed25519PrivateKey.generate()
    device_id = "BANTAI-TEST-001"
    setup_token = secrets.token_urlsafe(32)

    server = ProvisioningHandshake(
        device_id=device_id,
        identity_key=pi_identity_key,
        setup_token=setup_token,
    )

    # Simulate the Flutter app's ephemeral X25519 key and nonce.
    client_ephemeral = X25519PrivateKey.generate()
    client_public = raw_public_key(client_ephemeral)
    client_nonce = secrets.token_bytes(32)

    hello = canonical_json({
        "type": "client_hello",
        "client_ephemeral": encode64(client_public),
        "client_nonce": encode64(client_nonce),
    })

    response = json.loads(server.handle_client_hello(hello))

    assert response["type"] == "server_hello"

    # The app verifies the Pi against the public key obtained
    # from its trusted permanent QR identity.
    trusted_pi_public = pi_identity_key.public_key()

    transcript_data = {
        "version": 1,
        "device_id": device_id,
        "identity_public": encode64(raw_public_key(pi_identity_key)),
        "client_ephemeral": encode64(client_public),
        "client_nonce": encode64(client_nonce),
        "server_ephemeral": response["server_ephemeral"],
        "server_nonce": response["server_nonce"],
    }

    transcript = canonical_json(transcript_data)

    trusted_pi_public.verify(
        decode64(response["signature"], 64),
        PROTOCOL_PREFIX + transcript,
    )

    transcript_hash = hashlib.sha256(transcript).digest()

    assert decode64(response["transcript_hash"], 32) == transcript_hash

    # Derive the same session key on the client.
    server_public = X25519PrivateKey.from_private_bytes(
        client_ephemeral.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    peer_public = __import__(
        "cryptography.hazmat.primitives.asymmetric.x25519",
        fromlist=["X25519PublicKey"],
    ).X25519PublicKey.from_public_bytes(
        decode64(response["server_ephemeral"], 32)
    )

    client_session_key = derive_session_key(
        server_public.exchange(peer_public),
        transcript,
    )

    # Encrypt the one-time setup token for the Pi.
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps({
        "setup_token": setup_token
    }).encode("utf-8")

    ciphertext = AESGCM(client_session_key).encrypt(
        nonce,
        plaintext,
        transcript_hash,
    )

    authorization = canonical_json({
        "type": "authorize",
        "nonce": encode64(nonce),
        "ciphertext": encode64(ciphertext),
    })

    assert server.handle_authorization(authorization) is True
    assert server.authorized is True
    # Replaying the same authorization must fail.
    assert server.handle_authorization(authorization) is False

    print("PASS: Replayed authorization rejected")

    print("PASS: Pi identity signature verified")
    print("PASS: Both sides derived the same session key")
    print("PASS: Authorization token accepted")
    print("PASS: Setup session closed after authorization")


if __name__ == "__main__":
    test_successful_handshake()
