from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.api.routes import RegisterRequest, register
from app.core.auth import create_access_token, decode_token, hash_password, verify_password


class ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


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

    @pytest.mark.asyncio
    async def test_register_rejects_duplicate_email(self):
        db = AsyncMock()
        db.execute.return_value = ScalarResult(
            SimpleNamespace(username="existing-user", email="taken@example.com")
        )

        with pytest.raises(HTTPException) as exc_info:
            await register(
                RegisterRequest(
                    username="new-user",
                    password="secret123",
                    email="taken@example.com",
                ),
                db,
            )

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "Email already registered"
        db.add.assert_not_called()
        db.commit.assert_not_awaited()
