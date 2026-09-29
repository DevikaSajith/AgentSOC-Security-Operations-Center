"""The LLM provider interface.

A provider turns (system prompt, user prompt, optional JSON schema) into TEXT. That is all
an LLM can do in AgentSOC: it has no tools, no shell, no database and no network access
of its own. Whatever it returns is untrusted text that callers must parse and validate.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


class LLMError(Exception):
    """Base class for provider failures (messages never contain credentials or prompts)."""


class LLMUnavailableError(LLMError):
    """The model could not be reached (not running, timeout, connection refused, ...)."""


class LLMResponseError(LLMError):
    """The provider answered, but not with a usable completion."""


@dataclass(frozen=True)
class LLMResponse:
    text: str
    provider: str
    model: str
    duration_ms: int | None = None


@dataclass(frozen=True)
class LLMStatus:
    provider: str
    model: str
    reachable: bool
    model_available: bool | None = None
    detail: str = ""


class LLMProvider(ABC):
    """Implementations: OllamaProvider (local), MockLLMProvider (tests)."""

    name: str
    model: str

    @abstractmethod
    def complete(self, system: str, user: str, *,
                 json_schema: dict[str, Any] | None = None) -> LLMResponse:
        """One completion. Raises LLMUnavailableError / LLMResponseError."""

    @abstractmethod
    def status(self) -> LLMStatus:
        """Cheap reachability check (must not raise)."""
