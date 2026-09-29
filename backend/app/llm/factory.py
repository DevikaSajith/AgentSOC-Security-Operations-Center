"""Build the configured LLM provider. Only real providers are selectable by configuration;
the mock provider is injected directly by tests."""

import logging

from app.config import Settings
from app.llm.base import LLMProvider
from app.llm.ollama import OllamaProvider

logger = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = ("ollama", "none")


class LLMConfigurationError(ValueError):
    """LLM_PROVIDER / LLM_MODEL / OLLAMA_BASE_URL are invalid."""


def build_provider(settings: Settings) -> LLMProvider | None:
    """The provider named by LLM_PROVIDER, or None when LLM_PROVIDER=none."""
    name = settings.llm_provider.lower()
    if name == "none":
        return None
    if name == "ollama":
        try:
            return OllamaProvider(model=settings.llm_model, base_url=settings.ollama_base_url,
                                  timeout_seconds=settings.llm_timeout_seconds,
                                  num_ctx=settings.ollama_num_ctx)
        except ValueError as exc:
            raise LLMConfigurationError(str(exc)) from None
    raise LLMConfigurationError(
        f"unsupported LLM_PROVIDER '{settings.llm_provider}'. Supported: {', '.join(SUPPORTED_PROVIDERS)}")
