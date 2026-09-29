"""Investigation models.

InvestigationDecision   - the strict contract the LLM (or rule-based fallback) must satisfy.
                          It can only CITE evidence IDs, ANNOTATE existing timeline entries
                          and PROPOSE MITRE techniques. It cannot add evidence, events,
                          timestamps or entities.
InvestigationAssessment - what is stored on the incident: the deterministic evidence
                          catalog, timeline, entities and relationships built by the system,
                          plus the validated interpretation. MITRE status (candidate vs
                          confirmed) is decided by the backend, never by the model.
No hidden chain-of-thought is requested or stored - only concise rationale.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.enums import TriageMethod
from app.domain.events import utcnow

EvidenceId = str  # e.g. "EV3", "PR1", "RS2" - defined per run by the evidence catalog


class FindingType(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    OTHER = "other"


class Certainty(str, Enum):
    """How well a statement is supported. Only 'confirmed' may be presented as fact."""

    CONFIRMED = "confirmed"      # directly shown by cited observed evidence
    SUSPECTED = "suspected"      # strongly indicated, not directly shown
    POSSIBLE = "possible"        # consistent with evidence, weakly supported
    UNSUPPORTED = "unsupported"  # a stage with no evidence (listed to show the gap)


class InvestigationNextStep(str, Enum):
    COMPLIANCE_REVIEW = "compliance_review"  # hand to the Compliance Agent (later phase)
    ESCALATE = "escalate"                    # urgent human attention
    MONITOR = "monitor"                      # keep watching; not enough to act on
    CLOSE = "close"                          # benign; only allowed without confirmed findings


class MitreStatus(str, Enum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"


def _lower(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ------------------------------------------------------------------ LLM output
class TimelineNote(_Strict):
    evidence_id: EvidenceId
    significance: str = Field(min_length=3, max_length=200)


class AttackStageProposal(_Strict):
    stage: FindingType
    description: str = Field(min_length=5, max_length=300)
    evidence_ids: list[EvidenceId] = Field(default_factory=list, max_length=10)
    certainty: Certainty

    _enums = field_validator("stage", "certainty", mode="before")(lambda v: _lower(v))


class FindingProposal(_Strict):
    type: FindingType
    statement: str = Field(min_length=10, max_length=400)
    evidence_ids: list[EvidenceId] = Field(min_length=1, max_length=10)
    confidence: float = Field(ge=0.0, le=1.0)
    certainty: Certainty

    _enums = field_validator("type", "certainty", mode="before")(lambda v: _lower(v))


class MitreProposal(_Strict):
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[EvidenceId] = Field(min_length=1, max_length=10)
    rationale: str = Field(min_length=10, max_length=300)

    @field_validator("technique_id", mode="before")
    @classmethod
    def _upper(cls, value: Any) -> Any:
        return value.strip().upper() if isinstance(value, str) else value


class InvestigationDecision(_Strict):
    summary: str = Field(min_length=20, max_length=900)
    confidence: float = Field(ge=0.0, le=1.0, description="support for the conclusion by the evidence")
    timeline_notes: list[TimelineNote] = Field(min_length=1, max_length=40)
    attack_sequence: list[AttackStageProposal] = Field(min_length=1, max_length=8)
    findings: list[FindingProposal] = Field(min_length=1, max_length=10)
    mitre_techniques: list[MitreProposal] = Field(default_factory=list, max_length=8)
    root_cause_hypothesis: str = Field(min_length=10, max_length=500)
    unknowns: list[str] = Field(min_length=1, max_length=8)
    alternative_hypotheses: list[str] = Field(default_factory=list, max_length=5)
    recommended_next_step: InvestigationNextStep

    _step = field_validator("recommended_next_step", mode="before")(lambda v: _lower(v))

    @field_validator("unknowns", "alternative_hypotheses")
    @classmethod
    def _bounded_items(cls, value: list[str]) -> list[str]:
        if any(not 5 <= len(v.strip()) <= 300 for v in value):
            raise ValueError("items must be 5-300 characters")
        return [v.strip() for v in value]


# ------------------------------------------------------------------ stored
class EvidenceItem(BaseModel):
    """One evidence item, built deterministically from incident data (never by the model)."""

    evidence_id: EvidenceId
    type: str  # event | network | iam | resource | security_finding | monitor_finding | triage_assessment
    source: str  # CloudTrail, VPC Flow Logs, IAM, S3, EC2, GuardDuty, Security Hub, Monitor Agent, ...
    timestamp: datetime | None = None
    entity: str  # the main entity it is about, e.g. "alice" or "S3Bucket/company-data"
    description: str
    raw_reference: dict[str, Any] = Field(default_factory=dict)  # event_id / evidence_id / resource
    confidence: float = Field(ge=0.0, le=1.0)  # reliability of the item itself
    observed: bool  # True: telemetry/state; False: an earlier agent's assessment


class TimelineEntry(BaseModel):
    evidence_id: EvidenceId
    timestamp: datetime | None
    event_type: str
    source: str
    principal: str
    source_ip: str
    resource: str
    seconds_since_previous: float | None = None
    shared_with_previous: list[str] = Field(default_factory=list)  # same_principal, same_source_ip, ...
    significance: str | None = None  # model annotation (interpretation)


class Entity(BaseModel):
    entity_id: str
    type: str  # principal | source_ip | resource | instance | bucket | secret | account | region | access_key
    value: str
    evidence_ids: list[EvidenceId] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    source: str  # entity_id
    relation: str  # authenticated_from, acted_on, originated, created, connected_to, same_*...
    target: str  # entity_id
    evidence_ids: list[EvidenceId] = Field(default_factory=list)
    certainty: Certainty = Certainty.CONFIRMED


class AttackStage(BaseModel):
    order: int
    stage: FindingType
    description: str
    evidence_ids: list[EvidenceId]
    certainty: Certainty


class Finding(BaseModel):
    finding_id: str
    type: FindingType
    statement: str
    evidence_ids: list[EvidenceId]
    confidence: float = Field(ge=0.0, le=1.0)
    classification: Certainty


class MitreAssessment(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[EvidenceId]
    rationale: str
    status: MitreStatus
    validation_note: str  # why the backend marked it candidate/confirmed


class InvestigationAssessment(BaseModel):
    """The latest valid investigation of an incident (replaced on each successful run)."""

    status: str = "completed"
    run_id: str
    method: TriageMethod  # llm | rule_based_fallback
    provider: str
    model: str
    timestamp: datetime = Field(default_factory=utcnow)
    input_event_ids: list[str]
    based_on_triage_run: str | None
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    evidence: list[EvidenceItem]
    timeline: list[TimelineEntry]
    entities: list[Entity]
    relationships: list[Relationship]
    attack_sequence: list[AttackStage]
    findings: list[Finding]
    mitre_techniques: list[MitreAssessment]
    root_cause_hypothesis: str  # always a HYPOTHESIS, never presented as fact
    unknowns: list[str]
    limitations: list[str]  # system-derived gaps in the available evidence
    alternative_hypotheses: list[str]
    recommended_next_step: InvestigationNextStep
