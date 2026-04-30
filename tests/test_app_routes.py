from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException

from app.api.routes import ContextCreate, FileVerifyRequest, create_context, verify_file_for_rag
from app.db.tables import AuditLog, ContextRecord, DataSource
from app.main import app


def test_demo_routes_and_static_mount_are_registered():
    paths = {route.path for route in app.routes}

    assert "/demo/compare" in paths
    assert "/demo/live-compare" in paths
    assert "/api/v1/demo/session" in paths
    assert "/api/v1/live-demo/status" in paths
    assert "/static" in paths


class ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


@pytest.mark.asyncio
async def test_create_context_rejects_missing_authenticated_user():
    db = AsyncMock()
    db.add = Mock()
    db.execute.return_value = ScalarResult(None)

    with pytest.raises(HTTPException) as exc_info:
        await create_context(
            ContextCreate(content="context payload"),
            db,
            {"user_id": "ghost-user", "role": "agent"},
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Authenticated user not found"
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_context_audit_uses_authenticated_actor():
    db = AsyncMock()
    db.add = Mock()
    db.refresh = AsyncMock()
    db.execute.return_value = ScalarResult(
        SimpleNamespace(id="user-1", username="agent", email="agent@example.com")
    )

    response = await create_context(
        ContextCreate(content="safe context"),
        db,
        {"user_id": "user-1", "role": "agent"},
    )

    added_context = next(call.args[0] for call in db.add.call_args_list if isinstance(call.args[0], ContextRecord))
    added_audit = next(call.args[0] for call in db.add.call_args_list if isinstance(call.args[0], AuditLog))

    assert response.user_id == "user-1"
    assert added_context.user_id == "user-1"
    assert added_audit.user_id == "user-1"
    assert added_audit.details["actor_user_id"] == "user-1"
    assert added_audit.details["actor_role"] == "agent"
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_file_for_rag_safe_file_uses_ingest_first_flow():
    db = AsyncMock()
    db.add = Mock()

    response = await verify_file_for_rag(
        FileVerifyRequest(
            file_name="knowledge_base.md",
            file_content="Python is a high-level programming language.",
        ),
        db,
        {"user_id": "user-1", "role": "agent"},
    )

    added_source = next(call.args[0] for call in db.add.call_args_list if isinstance(call.args[0], DataSource))

    assert response.classification == "QUARANTINE"
    assert response.is_verified is False
    assert response.verification_details["ingest_status"] == "QUARANTINED"
    assert response.verification_details["eligible_for_trusted_memory"] is False
    assert added_source.source_type == "rag_ingest"
    assert added_source.is_active is False
    db.commit.assert_awaited_once()
