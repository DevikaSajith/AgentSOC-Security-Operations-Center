"""Typed loader for config/investigator_rules.yaml."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from app.domain.investigation import FindingType, InvestigationNextStep

INVESTIGATOR_RULES_FILE = "investigator_rules.yaml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ContextRules(_Strict):
    max_events: int = Field(ge=1, le=200)
    max_resources: int = Field(ge=0, le=50)
    max_string_length: int = Field(ge=40, le=2000)
    max_context_chars: int = Field(ge=2000, le=100_000)


class PolicyRules(_Strict):
    max_repair_attempts: int = Field(ge=0, le=3)
    high_confidence_threshold: float = Field(ge=0.0, le=1.0)
    high_confidence_min_evidence: int = Field(ge=1)
    confirmed_min_observed_evidence: int = Field(ge=1)
    critical_finding_types: tuple[FindingType, ...]
    critical_confirmed_min_evidence: int = Field(ge=1)
    mitre_min_evidence: int = Field(ge=1)
    summary_must_name_entity: bool
    close_forbidden_with_confirmed_findings: bool
    critical_findings_require_next_step: tuple[InvestigationNextStep, ...]


class MitreConfirmation(_Strict):
    min_confidence: float = Field(ge=0.0, le=1.0)
    require_relevant_event: bool


class FallbackRules(_Strict):
    confidence: float = Field(ge=0.0, le=1.0)
    finding_confidence: float = Field(ge=0.0, le=1.0)
    mitre_confidence: float = Field(ge=0.0, le=1.0)


class InvestigatorConfig(_Strict):
    context: ContextRules
    policy: PolicyRules
    mitre_confirmation: MitreConfirmation
    stage_by_event_type: dict[str, FindingType]
    fallback: FallbackRules


class InvestigatorConfigError(RuntimeError):
    """investigator_rules.yaml is missing or invalid."""


def load_investigator_config(config_dir: Path) -> InvestigatorConfig:
    path = config_dir / INVESTIGATOR_RULES_FILE
    if not path.is_file():
        raise InvestigatorConfigError(f"{INVESTIGATOR_RULES_FILE} not found in {config_dir}")
    try:
        return InvestigatorConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, ValueError) as exc:
        raise InvestigatorConfigError(f"invalid {INVESTIGATOR_RULES_FILE}: {exc}") from exc
