"""Shared "ask the LLM for a structured decision" loop used by reasoning agents.

    prompt -> provider.complete (text, JSON-schema constrained) -> validate(text)
      -> on DecisionValidationError: ONE constrained repair prompt (configurable) -> validate

The model's text is never trusted: `validate` must parse it and run every check.
Nothing here writes anything; the caller applies a decision only if one is returned.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Generic, TypeVar

from app.llm.base import LLMProvider, LLMResponseError, LLMUnavailableError

T = TypeVar("T")


class DecisionValidationError(ValueError):
    """code: invalid_json | schema_invalid | semantic_invalid | policy_violation | ..."""

    def __init__(self, code: str, problems: list[str]) -> None:
        super().__init__(f"{code}: {'; '.join(problems)}")
        self.code = code
        self.problems = problems


@dataclass
class StructuredOutcome(Generic[T]):
    value: T | None = None
    attempts: int = 0
    errors: list[str] = field(default_factory=list)
    failure: str = ""  # "" on success, else an outcome such as "llm_unavailable"


def ask_structured(provider: LLMProvider | None, system: str, user: str, schema: dict[str, Any],
                   validate: Callable[[str], T], repair: Callable[[str, list[str]], str],
                   max_repairs: int) -> StructuredOutcome[T]:
    outcome: StructuredOutcome[T] = StructuredOutcome()
    if provider is None:
        outcome.errors.append("no LLM provider configured (LLM_PROVIDER=none)")
        outcome.failure = "llm_not_configured"
        return outcome
    prompt = user
    for _ in range(1 + max_repairs):
        outcome.attempts += 1
        try:
            response = provider.complete(system, prompt, json_schema=schema)
        except LLMUnavailableError as exc:
            outcome.errors.append(f"llm_unavailable: {exc}")
            outcome.failure = "llm_unavailable"
            return outcome
        except LLMResponseError as exc:
            outcome.errors.append(f"llm_error: {exc}")
            outcome.failure = "llm_error"
            return outcome
        try:
            outcome.value = validate(response.text)
            outcome.failure = ""
            return outcome
        except DecisionValidationError as exc:
            outcome.errors.extend(f"{exc.code}: {p}" for p in exc.problems[:10])
            outcome.failure = ("policy_violation" if exc.code == "policy_violation"
                               else "invalid_llm_output")
            prompt = repair(response.text, exc.problems)
    return outcome
