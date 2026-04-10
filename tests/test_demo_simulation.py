import pytest

from app.core.demo_simulation import (
    DEFAULT_QUESTION,
    MALICIOUS_CONTEXT_EXAMPLE,
    SAFE_CONTEXT_EXAMPLE,
    DemoSimulationService,
)


@pytest.mark.asyncio
async def test_safe_context_is_accepted_by_protected_flow():
    service = DemoSimulationService()
    session = service.create_session()

    state = await service.submit_memory(
        session["session_id"],
        SAFE_CONTEXT_EXAMPLE,
        label="Безопасный контекст",
    )

    assert state["vulnerable"]["memory_count"] == 1
    assert state["protected"]["memory_count"] == 1
    assert state["protected"]["last_gate"]["accepted"] is True
    assert state["protected"]["last_gate"]["classification"] == "ACCEPT"
    assert state["protected"]["last_gate"]["details"]["signature_valid"] is True
    assert state["protected"]["last_gate"]["details"]["hash_chain_valid"] is True


@pytest.mark.asyncio
async def test_memory_injection_is_blocked_only_by_civs():
    service = DemoSimulationService()
    session = service.create_session()

    state = await service.submit_memory(
        session["session_id"],
        MALICIOUS_CONTEXT_EXAMPLE,
        label="Memory injection",
    )

    assert state["vulnerable"]["memory_count"] == 1
    assert state["vulnerable"]["compromised"] is True
    assert state["protected"]["memory_count"] == 0
    assert state["protected"]["last_gate"]["accepted"] is False
    assert state["protected"]["last_gate"]["classification"] == "REJECT"
    assert "prompt_injection" in state["protected"]["last_gate"]["detected_patterns"]

    state = service.ask_agent(session["session_id"], DEFAULT_QUESTION)

    assert state["vulnerable"]["last_response"] == "HACKED"
    assert state["protected"]["last_response"] != "HACKED"
