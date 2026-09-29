"""Deterministic LLM stand-in for automated tests (never selected by configuration)."""

from typing import Any, Callable

from app.llm.base import LLMProvider, LLMResponse, LLMStatus, LLMUnavailableError

Responder = Callable[[str, str], str]


class MockLLMProvider(LLMProvider):
    """Returns scripted completions.

    `responses` is either a list (returned in order; the last one repeats) or a function
    (system, user) -> text. `available=False` simulates an unreachable model.
    Every call is recorded in `calls` so tests can inspect what the model was sent.
    """

    name = "mock"

    def __init__(self, responses: list[str] | Responder | None = None, *,
                 model: str = "mock-triage-1", available: bool = True) -> None:
        self.model = model
        self._responses = responses if responses is not None else ["{}"]
        self._available = available
        self.calls: list[dict[str, Any]] = []

    def complete(self, system: str, user: str, *,
                 json_schema: dict[str, Any] | None = None) -> LLMResponse:
        self.calls.append({"system": system, "user": user, "json_schema": json_schema})
        if not self._available:
            raise LLMUnavailableError("mock provider configured as unavailable")
        if callable(self._responses):
            text = self._responses(system, user)
        else:
            text = self._responses[min(len(self.calls), len(self._responses)) - 1]
        return LLMResponse(text=text, provider=self.name, model=self.model, duration_ms=0)

    def status(self) -> LLMStatus:
        return LLMStatus(self.name, self.model, reachable=self._available,
                         model_available=self._available)
