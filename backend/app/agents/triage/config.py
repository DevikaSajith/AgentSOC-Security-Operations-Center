"""Typed loader for config/triage_rules.yaml."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from app.domain.enums import Priority, Severity

TRIAGE_RULES_FILE = "triage_rules.yaml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ContextRules(_Strict):
    max_events: int = Field(ge=1, le=200)
    max_resources: int = Field(ge=0, le=50)
    max_string_length: int = Field(ge=40, le=2000)
    max_context_chars: int = Field(ge=2000, le=100_000)


class PolicyRules(_Strict):
    min_confidence_to_close: float = Field(ge=0.0, le=1.0)
    close_forbidden_at_or_above: Severity
    p1_requires_severity_at_least: Severity
    critical_requires_priority_at_most: Priority
    max_repair_attempts: int = Field(ge=0, le=3)


class FallbackRules(_Strict):
    confidence: float = Field(ge=0.0, le=1.0)
    investigate_at_or_above: Severity
    escalate_to_critical_when: tuple[str, ...]
    priority_by_severity: dict[Severity, Priority]


class TriageConfig(_Strict):
    context: ContextRules
    policy: PolicyRules
    fallback: FallbackRules


class TriageConfigError(RuntimeError):
    """triage_rules.yaml is missing or invalid."""


def load_triage_config(config_dir: Path) -> TriageConfig:
    path = config_dir / TRIAGE_RULES_FILE
    if not path.is_file():
        raise TriageConfigError(f"{TRIAGE_RULES_FILE} not found in {config_dir}")
    try:
        return TriageConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, ValueError) as exc:
        raise TriageConfigError(f"invalid {TRIAGE_RULES_FILE}: {exc}") from exc
