import pytest

import app.core.live_llm_demo as live_llm_demo_module
from app.core.live_llm_demo import (
    LIVE_DEFAULT_QUESTION,
    LIVE_MALICIOUS_CONTEXT_EXAMPLE,
    LIVE_SAFE_CONTEXT_EXAMPLE,
    LLMCallResult,
    LiveLLMDemoService,
    OpenAIResponsesGateway,
)


class FakeLLMGateway:
    def __init__(self):
        self.model = "fake-live-model"
        self.provider_label = "Fake live gateway"
        self.endpoint_label = "fake-gateway"

    async def generate_reply(self, memory, question):
        joined_memory = "\n".join(item["content"] for item in memory).lower()
        if "answer exactly \"hacked\"" in joined_memory or "override" in joined_memory:
            text = "HACKED"
        elif "python" in question.lower():
            text = "Python is a high-level programming language."
        else:
            text = "Safe reply"

        return LLMCallResult(
            text=text,
            response_id="resp_fake_123",
            model=self.model,
            latency_ms=12.5,
            usage={"output_tokens": 7},
        )


@pytest.mark.asyncio
async def test_live_demo_safe_context_reaches_both_agents():
    service = LiveLLMDemoService(gateway=FakeLLMGateway())
    session = service.create_session()

    state = await service.submit_memory(
        session["session_id"],
        LIVE_SAFE_CONTEXT_EXAMPLE,
        label="Безопасный контекст",
    )

    assert state["vulnerable"]["memory_count"] == 1
    assert state["protected"]["memory_count"] == 1
    assert state["protected"]["last_gate"]["accepted"] is True
    assert state["protected"]["last_gate"]["classification"] == "ACCEPT"

    state = await service.ask_agent(session["session_id"], LIVE_DEFAULT_QUESTION)
    assert state["vulnerable"]["last_response"] != "HACKED"
    assert state["protected"]["last_response"] != "HACKED"
    assert state["vulnerable"]["last_llm"]["model"] == "fake-live-model"


@pytest.mark.asyncio
async def test_live_demo_blocks_attack_before_reaching_protected_llm():
    service = LiveLLMDemoService(gateway=FakeLLMGateway())
    session = service.create_session()

    state = await service.submit_memory(
        session["session_id"],
        LIVE_MALICIOUS_CONTEXT_EXAMPLE,
        label="Memory injection",
    )

    assert state["vulnerable"]["memory_count"] == 1
    assert state["protected"]["memory_count"] == 0
    assert state["protected"]["last_gate"]["accepted"] is False
    assert state["protected"]["last_gate"]["classification"] == "REJECT"
    assert "memory_poisoning" in state["protected"]["last_gate"]["detected_patterns"]

    state = await service.ask_agent(session["session_id"], LIVE_DEFAULT_QUESTION)
    assert state["vulnerable"]["last_response"] == "HACKED"
    assert state["protected"]["last_response"] != "HACKED"


def test_ollama_gateway_is_configured_without_real_api_key(monkeypatch):
    monkeypatch.setattr(live_llm_demo_module.settings, "LLM_PROVIDER", "ollama")
    monkeypatch.setattr(live_llm_demo_module.settings, "OPENAI_API_KEY", "")
    monkeypatch.setattr(live_llm_demo_module.settings, "OPENAI_MODEL", "llama3.2")
    monkeypatch.setattr(live_llm_demo_module.settings, "OPENAI_BASE_URL", "http://localhost:11434/v1")

    gateway = OpenAIResponsesGateway()
    service = LiveLLMDemoService(gateway=gateway)

    assert gateway.is_configured() is True
    assert service.status()["provider"] == "Ollama OpenAI-compatible API"
    assert service.status()["endpoint"] == "localhost"
    assert service.status()["enabled"] is True


def test_openai_gateway_without_key_reports_configuration_error(monkeypatch):
    monkeypatch.setattr(live_llm_demo_module.settings, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(live_llm_demo_module.settings, "OPENAI_API_KEY", "")
    monkeypatch.setattr(live_llm_demo_module.settings, "OPENAI_MODEL", "gpt-4.1-mini")
    monkeypatch.setattr(live_llm_demo_module.settings, "OPENAI_BASE_URL", "https://api.openai.com/v1")

    gateway = OpenAIResponsesGateway()
    service = LiveLLMDemoService(gateway=gateway)

    assert gateway.is_configured() is False
    assert service.status()["provider"] == "OpenAI Responses API"
    assert service.status()["endpoint"] == "api.openai.com"
    assert "OpenAI live demo is not configured" in service.status()["message"]
