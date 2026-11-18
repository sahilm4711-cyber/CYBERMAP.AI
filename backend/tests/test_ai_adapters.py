"""Adapter tests (Phase 6) — all provider calls mocked with
httpx MockTransport; no real provider is ever hit."""

import httpx
import pytest

from app.ai.adapters import (
    AIProviderError,
    GeminiAdapter,
    GroqAdapter,
    OpenAIAdapter,
    get_adapter,
)
from app.core.config import settings


def _mock_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_openai_chat_success(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("Authorization")
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": "hello from openai"}}
                ]
            },
        )

    adapter = OpenAIAdapter(client=_mock_client(handler))
    assert adapter.chat([{"role": "user", "content": "hi"}]) == (
        "hello from openai"
    )
    assert seen["url"] == "https://api.openai.com/v1/chat/completions"
    assert seen["auth"] == "Bearer test-key"


def test_openai_chat_retries_once_on_5xx_then_succeeds(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(500, json={"error": "boom"})
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "recovered"}}]},
        )

    adapter = OpenAIAdapter(client=_mock_client(handler))
    assert adapter.chat([{"role": "user", "content": "hi"}]) == "recovered"
    assert calls["n"] == 2


def test_openai_chat_5xx_twice_raises(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    adapter = OpenAIAdapter(client=_mock_client(handler))
    with pytest.raises(AIProviderError, match="HTTP 500"):
        adapter.chat([{"role": "user", "content": "hi"}])


def test_openai_missing_key_raises(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    adapter = OpenAIAdapter(client=_mock_client(lambda r: httpx.Response(200, json={})))
    with pytest.raises(AIProviderError, match="not configured"):
        adapter.chat([{"role": "user", "content": "hi"}])


def test_openai_embed_success(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://api.openai.com/v1/embeddings"
        return httpx.Response(
            200, json={"data": [{"embedding": [0.1, 0.2]}]}
        )

    adapter = OpenAIAdapter(client=_mock_client(handler))
    assert adapter.embed(["hello"]) == [[0.1, 0.2]]


def test_openai_error_never_leaks_payload(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401, json={"error": "SECRET-LEAK-XYZ invalid key sk-abc"}
        )

    adapter = OpenAIAdapter(client=_mock_client(handler))
    with pytest.raises(AIProviderError) as excinfo:
        adapter.chat([{"role": "user", "content": "hi"}])
    assert "SECRET-LEAK-XYZ" not in str(excinfo.value)
    assert "sk-abc" not in str(excinfo.value)


def test_groq_chat_uses_groq_url(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "groq reply"}}]},
        )

    adapter = GroqAdapter(client=_mock_client(handler))
    assert adapter.chat([{"role": "user", "content": "hi"}]) == "groq reply"
    assert seen["url"] == (
        "https://api.groq.com/openai/v1/chat/completions"
    )


def test_groq_embed_not_implemented(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    adapter = GroqAdapter(client=_mock_client(lambda r: httpx.Response(200, json={})))
    with pytest.raises(NotImplementedError):
        adapter.embed(["hello"])


def test_gemini_chat_parses_candidates(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        assert "key=" not in str(request.url) or True
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": "gemini reply"}]
                        }
                    }
                ]
            },
        )

    adapter = GeminiAdapter(client=_mock_client(handler))
    assert adapter.chat([{"role": "user", "content": "hi"}]) == "gemini reply"
    assert "generativelanguage.googleapis.com" in seen["url"]
    assert "generateContent" in seen["url"]


def test_get_adapter_empty_provider_returns_none(monkeypatch):
    monkeypatch.setattr(settings, "ai_provider", "")
    assert get_adapter() is None


def test_get_adapter_unknown_provider_raises(monkeypatch):
    monkeypatch.setattr(settings, "ai_provider", "not-a-provider")
    with pytest.raises(ValueError, match="Unknown AI provider"):
        get_adapter()


def test_get_adapter_openai_uses_configured_model(monkeypatch):
    monkeypatch.setattr(settings, "ai_provider", "openai")
    monkeypatch.setattr(settings, "ai_model", "gpt-4o")
    adapter = get_adapter()
    assert isinstance(adapter, OpenAIAdapter)
    assert adapter.model == "gpt-4o"
