from app.core.auth import create_access_token, decode_token, hash_password, verify_password


class TestAuth:
    """Тесты аутентификации и токенов."""

    def test_hash_password_and_verify(self):
        password = "test-password"
        hashed_password = hash_password(password)

        assert hashed_password != password
        assert verify_password(password, hashed_password) is True
        assert verify_password("wrong-password", hashed_password) is False

    def test_verify_password_supports_legacy_hashes(self):
        assert verify_password("secret", "hashed_secret") is True
        assert verify_password("other", "hashed_secret") is False

    def test_create_access_token_and_decode(self):
        token = create_access_token({"sub": "user-123", "role": "agent"})
        payload = decode_token(token)

        assert payload["sub"] == "user-123"
        assert payload["role"] == "agent"
        assert "exp" in payload
