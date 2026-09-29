"""Local Ollama provider (https://github.com/ollama/ollama). No API key, no internet.

Only the configured base URL is ever contacted, and only its /api/chat and /api/tags
endpoints. Output is requested as JSON constrained by the caller's schema, with
temperature 0 and the model's "thinking" mode disabled (we never want or store hidden
reasoning; any <think> text that still appears is stripped by the parser).
"""

import time
from typing import Any
from urllib.parse import urlparse

import httpx

from app.llm.base import LLMProvider, LLMResponse, LLMResponseError, LLMStatus, LLMUnavailableError


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, model: str, base_url: str = "http://localhost:11434",
                 timeout_seconds: float = 180, transport: httpx.BaseTransport | None = None,
                 num_ctx: int = 8192) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("OLLAMA_BASE_URL must be an http(s) URL")
        if parsed.path not in ("", "/") or parsed.query or parsed.username or parsed.password:
            raise ValueError("OLLAMA_BASE_URL must be a bare origin like http://localhost:11434")
        if not model or len(model) > 200:
            raise ValueError("LLM_MODEL must be a model name such as 'qwen3:4b'")
        self.model = model
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self._timeout = timeout_seconds
        if not 2048 <= num_ctx <= 131072:
            raise ValueError("OLLAMA_NUM_CTX must be between 2048 and 131072")
        self._num_ctx = num_ctx
        self._transport = transport  # injectable for tests

    def _client(self, timeout: float) -> httpx.Client:
        return httpx.Client(base_url=self.base_url, timeout=timeout, transport=self._transport,
                            follow_redirects=False, trust_env=False)

    def complete(self, system: str, user: str, *,
                 json_schema: dict[str, Any] | None = None) -> LLMResponse:
        body: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "think": False,
            "options": {"temperature": 0, "num_ctx": self._num_ctx},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "format": json_schema if json_schema is not None else "json",
        }
        started = time.monotonic()
        try:
            with self._client(self._timeout) as client:
                response = client.post("/api/chat", json=body)
        except httpx.TimeoutException:
            raise LLMUnavailableError(f"Ollama did not answer within {self._timeout:.0f}s") from None
        except httpx.HTTPError as exc:
            raise LLMUnavailableError(f"Ollama is not reachable at {self.base_url} "
                                      f"({type(exc).__name__})") from None
        if response.status_code == 404:
            raise LLMUnavailableError(f"model '{self.model}' is not available in Ollama "
                                      f"(run: ollama pull {self.model})")
        if response.status_code >= 400:
            raise LLMResponseError(f"Ollama returned HTTP {response.status_code}")
        try:
            content = response.json()["message"]["content"]
        except (ValueError, KeyError, TypeError):
            raise LLMResponseError("Ollama returned an unexpected response shape") from None
        if not isinstance(content, str) or not content.strip():
            raise LLMResponseError("Ollama returned an empty completion")
        return LLMResponse(text=content, provider=self.name, model=self.model,
                           duration_ms=int((time.monotonic() - started) * 1000))

    def status(self) -> LLMStatus:
        try:
            with self._client(3.0) as client:
                response = client.get("/api/tags")
            names = {m.get("name") for m in response.json().get("models", [])}
        except (httpx.HTTPError, ValueError, AttributeError):
            return LLMStatus(self.name, self.model, reachable=False,
                             detail=f"Ollama is not reachable at {self.base_url}")
        available = self.model in names or f"{self.model}:latest" in names
        return LLMStatus(self.name, self.model, reachable=True, model_available=available,
                         detail="" if available else f"model not pulled: ollama pull {self.model}")
