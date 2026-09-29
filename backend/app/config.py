"""Application settings, loaded from environment variables / a local .env file.

The database defaults to a SQLite file next to the backend so local development needs
no database server. Set DATABASE_URL to use PostgreSQL (or any SQLAlchemy URL) instead.
"""

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy.engine import make_url

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BACKEND_DIR.parent

# backend/.env first, then a repo-level .env; real environment variables always win.
load_dotenv(BACKEND_DIR / ".env")
load_dotenv(REPO_ROOT / ".env")

DEFAULT_DATABASE_URL = f"sqlite:///{(BACKEND_DIR / 'agentsoc.db').as_posix()}"
DEFAULT_CORS_ORIGINS = ("http://localhost:3000", "http://127.0.0.1:3000")
# Local-first defaults (overridable; nothing requires internet access or an API key).
DEFAULT_LLM_PROVIDER = "ollama"
DEFAULT_LLM_MODEL = "qwen3:4b"


class ConfigurationError(RuntimeError):
    """Raised when a setting is present but invalid."""


@dataclass(frozen=True)
class Settings:
    """Runtime settings. Credentials live only in the environment, never in code."""

    database_url: str = DEFAULT_DATABASE_URL
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    cors_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS
    config_dir: Path = REPO_ROOT / "config"
    # LLM used by reasoning agents (Triage). The dataclass default is "none" (no LLM, e.g.
    # in tests); get_settings() defaults to local Ollama. See app/llm/factory.py.
    llm_provider: str = "none"
    llm_model: str = ""
    ollama_base_url: str = "http://localhost:11434"
    llm_timeout_seconds: int = 180
    ollama_num_ctx: int = 8192  # context window; Ollama's default may truncate agent prompts

    @property
    def database_backend(self) -> str:
        """'sqlite', 'postgresql', ... (the SQLAlchemy dialect name)."""
        return make_url(self.database_url).get_backend_name()


def _int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigurationError(f"{name} must be an integer, got '{raw}'") from None


def get_settings() -> Settings:
    """Read settings from the environment (empty values fall back to defaults)."""
    database_url = os.getenv("DATABASE_URL", "").strip() or DEFAULT_DATABASE_URL
    try:
        make_url(database_url)
    except Exception:
        raise ConfigurationError("DATABASE_URL is not a valid SQLAlchemy URL") from None
    origins = os.getenv("CORS_ORIGINS", "").strip()
    config_dir = os.getenv("CONFIG_DIR", "").strip()
    return Settings(
        database_url=database_url,
        host=os.getenv("BACKEND_HOST", "").strip() or "127.0.0.1",
        port=_int("BACKEND_PORT", 8000),
        log_level=(os.getenv("LOG_LEVEL", "").strip() or "INFO").upper(),
        cors_origins=tuple(o.strip() for o in origins.split(",") if o.strip())
        if origins else DEFAULT_CORS_ORIGINS,
        config_dir=Path(config_dir) if config_dir else REPO_ROOT / "config",
        llm_provider=(os.getenv("LLM_PROVIDER", "").strip() or DEFAULT_LLM_PROVIDER).lower(),
        llm_model=os.getenv("LLM_MODEL", "").strip() or DEFAULT_LLM_MODEL,
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "").strip() or "http://localhost:11434",
        llm_timeout_seconds=_int("LLM_TIMEOUT_SECONDS", 180),
        ollama_num_ctx=_int("OLLAMA_NUM_CTX", 8192),
    )


def safe_database_url(url: str) -> str:
    """Return the URL with the password masked, safe to log."""
    return make_url(url).render_as_string(hide_password=True)


def configure_logging(level: str = "INFO") -> None:
    """Configure readable, uniform logging for the whole application."""
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
