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

        # Accept the token once, then close this handshake session.
        self.authorized = True
        self._token_consumed = True
        self._setup_token_hash = b""
        self._close_session()

        return True

    def _close_session(self) -> None:
        """Discard ephemeral session material."""
        self._session_key = None
        self._transcript_hash = None
        self._deadline = None
