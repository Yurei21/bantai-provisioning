
import json
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from bantai_provisioning.security import (
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


def make_session(setup_token):
    """Simulate a client establishing a session with the Pi."""
    identity_key = Ed25519PrivateKey.generate()

    server = ProvisioningHandshake(
        device_id="BANTAI-NEGATIVE-TEST",
        identity_key=identity_key,
        setup_token=setup_token,
    )

    client_ephemeral = X25519PrivateKey.generate()
    client_nonce = secrets.token_bytes(32)

    hello = canonical_json({
        "type": "client_hello",
        "client_ephemeral": encode64(raw_public_key(client_ephemeral)),
        "client_nonce": encode64(client_nonce),
    })

    response = json.loads(server.handle_client_hello(hello))

    # Reconstruct the same transcript used by the Pi.
    transcript = canonical_json({
        "version": 1,
        "device_id": "BANTAI-NEGATIVE-TEST",
        "identity_public": encode64(raw_public_key(identity_key)),
        "client_ephemeral": encode64(raw_public_key(client_ephemeral)),
        "client_nonce": encode64(client_nonce),
        "server_ephemeral": response["server_ephemeral"],
        "server_nonce": response["server_nonce"],
    })

    peer_public = X25519PublicKey.from_public_bytes(
        decode64(response["server_ephemeral"], 32)
    )

    session_key = derive_session_key(
        client_ephemeral.exchange(peer_public),
        transcript,
    )

    transcript_hash = decode64(response["transcript_hash"], 32)

    return server, session_key, transcript_hash


def make_authorization(session_key, transcript_hash, token):
    nonce = secrets.token_bytes(12)

    ciphertext = AESGCM(session_key).encrypt(
        nonce,
        json.dumps({"setup_token": token}).encode(),
        transcript_hash,
    )

    return canonical_json({
        "type": "authorize",
        "nonce": encode64(nonce),
        "ciphertext": encode64(ciphertext),
    })


def test_wrong_token_rejected():
    correct_token = secrets.token_urlsafe(32)
    server, key, transcript_hash = make_session(correct_token)

    message = make_authorization(
        key,
        transcript_hash,
        "definitely-the-wrong-token",
    )

    assert server.handle_authorization(message) is False
    assert server.authorized is False
    print("PASS: Incorrect setup token rejected")


def test_tampered_ciphertext_rejected():
    token = secrets.token_urlsafe(32)
    server, key, transcript_hash = make_session(token)

    message = json.loads(
        make_authorization(key, transcript_hash, token).decode()
    )

    ciphertext = bytearray(decode64(message["ciphertext"]))
    ciphertext[0] ^= 1
    message["ciphertext"] = encode64(bytes(ciphertext))

    assert server.handle_authorization(canonical_json(message)) is False
    assert server.authorized is False
    print("PASS: Tampered ciphertext rejected")


if __name__ == "__main__":
    test_wrong_token_rejected()
    test_tampered_ciphertext_rejected()
    print("All negative handshake tests passed.")
