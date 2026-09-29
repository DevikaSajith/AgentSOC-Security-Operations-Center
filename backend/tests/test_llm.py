"""LLM provider layer. No test here (or anywhere) contacts a real model: Ollama HTTP is
replaced by httpx.MockTransport."""

import json

import httpx
import pytest

from app.config import Settings, get_settings
from app.llm.base import LLMResponseError, LLMUnavailableError
from app.llm.factory import LLMConfigurationError, build_provider
from app.llm.mock import MockLLMProvider
from app.llm.ollama import OllamaProvider
from app.llm.parsing import JSONExtractionError, extract_json_object


def ollama(handler, **kwargs) -> OllamaProvider:
    return OllamaProvider("qwen3:4b", "http://localhost:11434",
                          transport=httpx.MockTransport(handler), **kwargs)


# ------------------------------------------------------------------ configuration
def test_default_configuration_is_local_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LLM_PROVIDER", "LLM_MODEL", "OLLAMA_BASE_URL"):
        monkeypatch.setenv(name, "")
    settings = get_settings()
    assert (settings.llm_provider, settings.llm_model, settings.ollama_base_url) == (
        "ollama", "qwen3:4b", "http://localhost:11434")
    provider = build_provider(settings)
    assert isinstance(provider, OllamaProvider) and provider.model == "qwen3:4b"


def test_model_and_url_are_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "OLLAMA")
    monkeypatch.setenv("LLM_MODEL", "llama3.2:3b")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://10.0.0.5:11434")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "30")
    provider = build_provider(get_settings())
    assert provider.model == "llama3.2:3b" and provider.base_url == "http://10.0.0.5:11434"


def test_provider_none_and_invalid_configuration() -> None:
    assert build_provider(Settings(llm_provider="none")) is None
    with pytest.raises(LLMConfigurationError):
        build_provider(Settings(llm_provider="openai", llm_model="gpt"))
    with pytest.raises(LLMConfigurationError):
        build_provider(Settings(llm_provider="ollama", llm_model="m",
                                ollama_base_url="file:///etc/passwd"))
    with pytest.raises(LLMConfigurationError):  # only a bare origin, no smuggled paths
        build_provider(Settings(llm_provider="ollama", llm_model="m",
                                ollama_base_url="http://evil.example/api?x=1"))
    with pytest.raises(LLMConfigurationError):
        build_provider(Settings(llm_provider="ollama", llm_model=""))


# ------------------------------------------------------------------ Ollama provider
def test_ollama_request_is_constrained_and_local() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"message": {"role": "assistant", "content": '{"ok": true}'}})

    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    response = ollama(handler).complete("system text", "user text", json_schema=schema)
    assert response.text == '{"ok": true}' and response.provider == "ollama"
    assert seen["url"] == "http://localhost:11434/api/chat"
    body = seen["body"]
    assert body["model"] == "qwen3:4b" and body["stream"] is False
    assert body["think"] is False and body["options"] == {"temperature": 0, "num_ctx": 8192}
    assert body["format"] == schema
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert "tools" not in body  # the model is never offered tools


def test_ollama_unreachable_is_reported_as_unavailable() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(LLMUnavailableError, match="not reachable"):
        ollama(refuse).complete("s", "u")
    assert ollama(refuse).status().reachable is False


def test_ollama_timeout_and_missing_model() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    with pytest.raises(LLMUnavailableError, match="did not answer"):
        ollama(slow).complete("s", "u")
    with pytest.raises(LLMUnavailableError, match="ollama pull"):
        ollama(lambda r: httpx.Response(404, json={"error": "model not found"})).complete("s", "u")


@pytest.mark.parametrize("response", [
    httpx.Response(500, text="boom"),
    httpx.Response(200, text="not json"),
    httpx.Response(200, json={"unexpected": "shape"}),
    httpx.Response(200, json={"message": {"content": "   "}}),
])
def test_ollama_malformed_responses(response: httpx.Response) -> None:
    with pytest.raises(LLMResponseError):
        ollama(lambda r: response).complete("s", "u")


def test_ollama_status_reports_model_availability() -> None:
    tags = {"models": [{"name": "qwen3:4b"}]}
    assert ollama(lambda r: httpx.Response(200, json=tags)).status().model_available is True
    other = OllamaProvider("llama3:8b", transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json=tags))).status()
    assert other.reachable and other.model_available is False and "ollama pull" in other.detail


# ------------------------------------------------------------------ mock provider
def test_mock_provider_is_deterministic_and_records_calls() -> None:
    mock = MockLLMProvider(["first", "second"])
    assert [mock.complete("s", "u").text for _ in range(3)] == ["first", "second", "second"]
    assert len(mock.calls) == 3 and mock.calls[0]["user"] == "u"
    echo = MockLLMProvider(lambda system, user: user.upper())
    assert echo.complete("s", "abc").text == "ABC"
    with pytest.raises(LLMUnavailableError):
        MockLLMProvider(available=False).complete("s", "u")


# ------------------------------------------------------------------ JSON extraction
@pytest.mark.parametrize("text", [
    '{"a": 1}',
    '<think>private reasoning {"a": 2}</think>{"a": 1}',
    'Sure! ```json\n{"a": 1}\n``` done',
    'prefix {"a": 1} trailing words',
])
def test_json_extraction(text: str) -> None:
    assert extract_json_object(text) == {"a": 1}


@pytest.mark.parametrize("text", ["no json here", '{"a": ', "[1, 2]", "x" * 20_001])
def test_json_extraction_failures(text: str) -> None:
    with pytest.raises(JSONExtractionError):
        extract_json_object(text)
