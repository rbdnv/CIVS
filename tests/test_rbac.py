from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException

from app.api.routes import ContextVerifyRequest, register, verify_context
from app.core.auth import decode_token
from app.models.auth import RegisterRequest


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


@pytest.mark.asyncio
async def test_agent_cannot_verify_foreign_context(monkeypatch):
    db = AsyncMock()
    db.add = Mock()
    db.execute.return_value = ScalarResult(
        SimpleNamespace(
            id="ctx-1",
            user_id="owner-1",
            content="safe content",
            content_hash="hash-1",
            previous_hash=None,
            created_at=datetime.now(UTC).replace(tzinfo=None),
            data_source_id=None,
            signature=None,
            public_key=None,
        )
    )

    async def fake_verify_context(*args, **kwargs):
        raise AssertionError("verification should not start for forbidden access")

    monkeypatch.setattr("app.api.routes.verifier_service.verify_context", fake_verify_context)

    with pytest.raises(HTTPException) as exc_info:
        await verify_context(
            ContextVerifyRequest(context_id="ctx-1"),
            db,
            {"user_id": "intruder-2", "role": "agent"},
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Access denied: can only access your own contexts"
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_owner_can_verify_own_context(monkeypatch):
    db = AsyncMock()
    db.add = Mock()
    db.execute.return_value = ScalarResult(
        SimpleNamespace(
            id="ctx-2",
            user_id="owner-1",
            content="safe content",
            content_hash="hash-2",
            previous_hash=None,
            created_at=datetime.now(UTC).replace(tzinfo=None),
            data_source_id=None,
            signature=None,
            public_key=None,
            trust_score=None,
            classification=None,
            verified_at=None,
        )
    )

    async def fake_verify_context(*args, **kwargs):
        return 0.75, "ACCEPT", {
            "signature_valid": False,
            "hash_chain_valid": True,
            "timestamp_fresh": True,
            "tampering_detected": False,
            "replay_attack_detected": False,
            "source_trusted": False,
        }

    monkeypatch.setattr("app.api.routes.verifier_service.verify_context", fake_verify_context)
    monkeypatch.setattr("app.api.routes.verifier_service.finalize_verification", lambda *args, **kwargs: (0.75, "ACCEPT"))
    monkeypatch.setattr("app.api.routes.security_service.detect_tampering", lambda *args, **kwargs: False)
    monkeypatch.setattr("app.api.routes.security_service.detect_replay_attack", lambda *args, **kwargs: False)

    response = await verify_context(
        ContextVerifyRequest(context_id="ctx-2"),
        db,
        {"user_id": "owner-1", "role": "agent"},
    )

    assert response.context_id == "ctx-2"
    assert response.classification == "ACCEPT"
    assert response.is_valid is True
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_admin_can_verify_foreign_context(monkeypatch):
    db = AsyncMock()
    db.add = Mock()
    db.execute.return_value = ScalarResult(
        SimpleNamespace(
            id="ctx-3",
            user_id="owner-1",
            content="safe content",
            content_hash="hash-3",
            previous_hash=None,
            created_at=datetime.now(UTC).replace(tzinfo=None),
            data_source_id=None,
            signature=None,
            public_key=None,
            trust_score=None,
            classification=None,
            verified_at=None,
        )
    )

    async def fake_verify_context(*args, **kwargs):
        return 0.75, "ACCEPT", {
            "signature_valid": False,
            "hash_chain_valid": True,
            "timestamp_fresh": True,
            "tampering_detected": False,
            "replay_attack_detected": False,
            "source_trusted": False,
        }

    monkeypatch.setattr("app.api.routes.verifier_service.verify_context", fake_verify_context)
    monkeypatch.setattr("app.api.routes.verifier_service.finalize_verification", lambda *args, **kwargs: (0.75, "ACCEPT"))
    monkeypatch.setattr("app.api.routes.security_service.detect_tampering", lambda *args, **kwargs: False)
    monkeypatch.setattr("app.api.routes.security_service.detect_replay_attack", lambda *args, **kwargs: False)

    response = await verify_context(
        ContextVerifyRequest(context_id="ctx-3"),
        db,
        {"user_id": "admin-1", "role": "admin"},
    )

    assert response.context_id == "ctx-3"
    assert response.classification == "ACCEPT"
    assert response.is_valid is True
    db.commit.assert_awaited_once()
