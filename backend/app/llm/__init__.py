"""LLM access for reasoning agents.

An LLM in AgentSOC only ever produces TEXT. It never executes anything: agents parse its
output, validate it with Pydantic plus semantic/policy checks, and only then act - and any
cloud action would still have to be a ToolRequest through app.tools.ToolExecutor.
"""

from app.llm.base import (
    LLMError,
    LLMProvider,
    LLMResponse,
    LLMResponseError,
    LLMStatus,
    LLMUnavailableError,
)
from app.llm.factory import LLMConfigurationError, build_provider
from app.llm.mock import MockLLMProvider
from app.llm.ollama import OllamaProvider

__all__ = ["LLMConfigurationError", "LLMError", "LLMProvider", "LLMResponse", "LLMResponseError",
           "LLMStatus", "LLMUnavailableError", "MockLLMProvider", "OllamaProvider", "build_provider"]
