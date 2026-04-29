from unittest.mock import AsyncMock, Mock

import pytest

from app.api.routes import RegisterRequest, register
from app.core.auth import decode_token


class ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


@pytest.mark.asyncio
async def test_public_register_cannot_grant_admin_role():
    db = AsyncMock()
    db.add = Mock()
    db.execute.return_value = ScalarResult(None)

    response = await register(
        RegisterRequest(
            username="attacker",
            password="secret123",
            email="attacker@example.com",
            is_admin=True,
        ),
        db,
    )

    added_user = db.add.call_args_list[0].args[0]
    token_payload = decode_token(response.access_token)

    assert added_user.is_admin is False
    assert response.role == "agent"
    assert token_payload["role"] == "agent"
    db.commit.assert_awaited_once()
