"""Triage models.

TriageDecision   - the strict contract an LLM (or the rule-based fallback) must satisfy.
                   It may only REFERENCE evidence by the short refs given in its context.
TriageAssessment - what is stored on the incident. It keeps two things apart:
                   * observed_evidence: facts copied by the SYSTEM from the incident data
                     for each referenced item (never model-written text), and
                   * interpretation: the model's classification, summary and rationale.
No hidden chain-of-thought is requested or stored - only concise decision rationale.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.enums import (
    IncidentCategory,
    Priority,
    Severity,
    TriageMethod,
    TriageNextStep,
)
from app.domain.events import utcnow

EvidenceRef = str  # e.g. "EV1", "RS2" - defined per run by the triage context


def _lower(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


class RiskIndicator(BaseModel):
    """An interpreted risk signal, tied to the evidence it is based on."""

    model_config = ConfigDict(extra="forbid")

    indicator: str = Field(min_length=3, max_length=160)
    evidence_refs: list[EvidenceRef] = Field(min_length=1, max_length=6)


class TriageDecision(BaseModel):
    """Structured triage output. Unknown fields, bad enums and out-of-range values fail."""

    model_config = ConfigDict(extra="forbid")

    severity: Severity
    priority: Priority
    category: IncidentCategory
    confidence: float = Field(ge=0.0, le=1.0, description="confidence in THIS assessment")
    classification: str = Field(min_length=3, max_length=80)
    summary: str = Field(min_length=10, max_length=600)
    severity_rationale: str = Field(min_length=10, max_length=400)
    priority_rationale: str = Field(min_length=10, max_length=400)
    risk_indicators: list[RiskIndicator] = Field(min_length=1, max_length=8)
    key_evidence: list[EvidenceRef] = Field(min_length=1, max_length=10)
    investigation_required: bool
    investigation_reason: str = Field(min_length=5, max_length=400)
    recommended_next_step: TriageNextStep

    # Accept "HIGH" / "IAM" / "INVESTIGATE" / "p1": case only, never a different value.
    _lower_enums = field_validator("severity", "category", "recommended_next_step",
                                   mode="before")(lambda v: _lower(v))

    @field_validator("priority", mode="before")
    @classmethod
    def _upper_priority(cls, value: Any) -> Any:
        return value.strip().upper() if isinstance(value, str) else value


class ObservedFact(BaseModel):
    """A fact taken from the incident data (system-generated, not model text)."""

    ref: EvidenceRef
    kind: str  # "event", "resource", "principal", "monitor_finding"
    fact: str
    event_id: str | None = None
    evidence_id: str | None = None


class TriageInterpretation(BaseModel):
    """The model's (or fallback's) interpretation - explicitly NOT raw evidence."""

    classification: str
    summary: str
    severity_rationale: str
    priority_rationale: str
    risk_indicators: list[RiskIndicator] = Field(default_factory=list)
    investigation_reason: str


class PriorAssessment(BaseModel):
    """The Monitor Agent's initial signal that triage started from."""

    severity: Severity
    priority: Priority | None
    category: IncidentCategory
    confidence: float = Field(ge=0.0, le=1.0)


class TriageAssessment(BaseModel):
    """The latest valid triage of an incident (replaced on every successful run)."""

    run_id: str
    method: TriageMethod
    provider: str
    model: str
    timestamp: datetime = Field(default_factory=utcnow)
    input_event_ids: list[str]
    severity: Severity
    priority: Priority
    category: IncidentCategory
    confidence: float = Field(ge=0.0, le=1.0)
    previous: PriorAssessment
    observed_evidence: list[ObservedFact]
    interpretation: TriageInterpretation
    investigation_required: bool
    recommended_next_step: TriageNextStep
