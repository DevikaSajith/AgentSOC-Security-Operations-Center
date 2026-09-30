"""Compliance models.

ComplianceDecision   - the strict contract the LLM (or rule-based fallback) must satisfy. It can only
                       CITE evidence ids and REFER to controls/frameworks/rules that exist in
                       config/compliance_mapping.yaml. It cannot add assets, evidence, frameworks,
                       controls, regulations or deadlines.
ComplianceAssessment - what is stored on the incident: backend-built facts (assets, data
                       classification, matched rules, configured mappings, standing unknowns) plus the
                       validated interpretation. Final statuses and the overall status are decided by
                       the backend; the model's proposals are stored alongside with a note.
This is a security-engineering aid, not legal advice: nothing here asserts a legal obligation.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.enums import TriageMethod
from app.domain.events import utcnow
from app.domain.investigation import EvidenceItem

EvidenceId = str


class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    POTENTIAL_GAP = "potential_gap"
    POTENTIAL_VIOLATION = "potential_violation"
    VIOLATION = "violation"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


# Severity order used to derive the overall status (unknown / not_applicable do not count).
STATUS_RANK = {ComplianceStatus.COMPLIANT: 0, ComplianceStatus.POTENTIAL_GAP: 1,
               ComplianceStatus.POTENTIAL_VIOLATION: 2, ComplianceStatus.VIOLATION: 3}
ADVERSE_STATUSES = {ComplianceStatus.POTENTIAL_GAP, ComplianceStatus.POTENTIAL_VIOLATION,
                    ComplianceStatus.VIOLATION}


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SENSITIVE = "sensitive"
    UNKNOWN = "unknown"


class ReportingStatus(str, Enum):
    """`configured_requirement` needs a matched rule from compliance_mapping.yaml (internal
    process rules only). There is deliberately no status for legal or statutory duties."""

    CONFIGURED_REQUIREMENT = "configured_requirement"
    INTERNAL_REVIEW_RECOMMENDED = "internal_review_recommended"
    REQUIRES_MANUAL_ASSESSMENT = "requires_manual_assessment"
    NOT_APPLICABLE = "not_applicable"


class RecommendationType(str, Enum):
    REVIEW_IAM_PRIVILEGES = "review_iam_privileges"
    REVIEW_ACCESS_CONTROL_CONFIGURATION = "review_access_control_configuration"
    VALIDATE_LOGGING_COVERAGE = "validate_logging_coverage"
    REVIEW_CREDENTIAL_ROTATION = "review_credential_rotation"
    PERFORM_COMPLIANCE_TEAM_ASSESSMENT = "perform_compliance_team_assessment"
    REVIEW_RESOURCE_CLASSIFICATION = "review_resource_classification"
    REVIEW_NETWORK_CONTROLS = "review_network_controls"
    REVIEW_DATA_PROTECTION_CONTROLS = "review_data_protection_controls"


def _lower(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ------------------------------------------------------------------ LLM output
class ControlAssessmentProposal(_Strict):
    control_id: str = Field(min_length=2, max_length=60)
    status: ComplianceStatus
    evidence_ids: list[EvidenceId] = Field(max_length=10)  # [] only for unknown / not_applicable
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=10, max_length=300)

    _status = field_validator("status", mode="before")(lambda v: _lower(v))


class FrameworkAssessmentProposal(_Strict):
    framework: str = Field(min_length=2, max_length=40)
    framework_control_id: str = Field(min_length=1, max_length=30)
    control_id: str = Field(min_length=2, max_length=60)
    status: ComplianceStatus
    evidence_ids: list[EvidenceId] = Field(max_length=10)
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=10, max_length=300)

    _status = field_validator("status", mode="before")(lambda v: _lower(v))


class GapProposal(_Strict):
    control_id: str = Field(min_length=2, max_length=60)
    description: str = Field(min_length=10, max_length=300)
    evidence_ids: list[EvidenceId] = Field(min_length=1, max_length=10)


class ViolationProposal(_Strict):
    control_id: str = Field(min_length=2, max_length=60)
    rule_id: str | None  # a configured violation rule id, or null
    status: ComplianceStatus
    statement: str = Field(min_length=10, max_length=300)
    evidence_ids: list[EvidenceId] = Field(min_length=1, max_length=10)

    _status = field_validator("status", mode="before")(lambda v: _lower(v))


class ReportingProposal(_Strict):
    status: ReportingStatus
    rule_id: str | None  # a configured reporting rule id, or null
    note: str = Field(min_length=5, max_length=300)
    evidence_ids: list[EvidenceId] = Field(max_length=10)

    _status = field_validator("status", mode="before")(lambda v: _lower(v))


class RecommendationProposal(_Strict):
    type: RecommendationType
    control_id: str | None
    rationale: str = Field(min_length=10, max_length=300)
    evidence_ids: list[EvidenceId] = Field(max_length=10)

    _type = field_validator("type", mode="before")(lambda v: _lower(v))


class ComplianceDecision(_Strict):
    # Every field is REQUIRED (no defaults): with schema-constrained decoding, optional keys are
    # often omitted by small models. Lists may be empty where noted in the prompt.
    summary: str = Field(min_length=20, max_length=800)
    confidence: float = Field(ge=0.0, le=1.0, description="confidence in THIS compliance assessment")
    control_assessments: list[ControlAssessmentProposal] = Field(min_length=1, max_length=8)
    framework_assessments: list[FrameworkAssessmentProposal] = Field(max_length=12)
    control_gaps: list[GapProposal] = Field(max_length=8)
    potential_violations: list[ViolationProposal] = Field(max_length=8)
    reporting_considerations: list[ReportingProposal] = Field(min_length=1, max_length=5)
    recommendations: list[RecommendationProposal] = Field(min_length=1, max_length=8)
    unknowns: list[str] = Field(min_length=1, max_length=8)

    @field_validator("unknowns")
    @classmethod
    def _bounded_items(cls, value: list[str]) -> list[str]:
        if any(not 5 <= len(v.strip()) <= 300 for v in value):
            raise ValueError("items must be 5-300 characters")
        return [v.strip() for v in value]


# ------------------------------------------------------------------ stored
class AffectedAsset(BaseModel):
    """A backend-built (observed) asset record; classification comes only from configuration."""

    asset_id: str  # AS1, AS2 ... (also usable as evidence id)
    asset_type: str
    identifier: str
    classification: DataClassification
    classification_basis: str
    environment: str | None = None
    owner: str | None = None  # None = unknown
    state: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[EvidenceId] = Field(default_factory=list)


class AffectedData(BaseModel):
    asset_id: str
    identifier: str
    classification: DataClassification
    basis: str


class ControlAssessment(BaseModel):
    control_id: str
    control_name: str
    status: ComplianceStatus  # final, decided by the backend rules
    proposed_status: ComplianceStatus  # what the model proposed
    evidence_ids: list[EvidenceId]
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str  # interpretation
    note: str | None = None  # why the backend changed the status (if it did)


class FrameworkAssessment(BaseModel):
    framework: str
    framework_name: str
    framework_control_id: str
    framework_control_title: str
    control_id: str
    status: ComplianceStatus
    evidence_ids: list[EvidenceId]
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    source: str  # "llm" (model-written) | "derived" (inherited from the control by the backend)
    note: str | None = None


class ControlGap(BaseModel):
    control_id: str
    control_name: str
    description: str
    evidence_ids: list[EvidenceId]


class PotentialViolation(BaseModel):
    control_id: str
    control_name: str
    rule_id: str | None
    status: ComplianceStatus
    proposed_status: ComplianceStatus
    statement: str
    evidence_ids: list[EvidenceId]
    note: str | None = None


class ReportingConsideration(BaseModel):
    status: ReportingStatus
    rule_id: str | None
    requirement: str | None = None  # from the matched configured rule
    note: str
    evidence_ids: list[EvidenceId] = Field(default_factory=list)
    source: str  # "llm" | "configured_rule"


class Recommendation(BaseModel):
    type: RecommendationType
    control_id: str | None
    rationale: str
    evidence_ids: list[EvidenceId] = Field(default_factory=list)


class RuleMatch(BaseModel):
    rule_id: str
    description: str
    control_id: str | None = None
    requirement: str | None = None
    evidence_ids: list[EvidenceId] = Field(default_factory=list)


class ComplianceAssessment(BaseModel):
    """The latest valid compliance assessment of an incident (replaced on each successful run)."""

    status: str = "completed"
    run_id: str
    method: TriageMethod  # llm | rule_based_fallback
    provider: str
    model: str
    timestamp: datetime = Field(default_factory=utcnow)
    input_event_ids: list[str]
    based_on_investigation_run: str | None
    confidence: float = Field(ge=0.0, le=1.0)
    overall_status: ComplianceStatus  # derived by the backend from the control statuses
    overall_note: str
    summary: str
    affected_assets: list[AffectedAsset]
    affected_data: list[AffectedData]
    controls: list[ControlAssessment]
    framework_assessments: list[FrameworkAssessment]
    control_gaps: list[ControlGap]
    potential_violations: list[PotentialViolation]
    reporting_status: ReportingStatus
    reporting_considerations: list[ReportingConsideration]
    recommendations: list[Recommendation]
    unknowns: list[str]  # model-stated
    standing_unknowns: list[str]  # backend-derived: what the configuration cannot answer
    matched_violation_rules: list[RuleMatch]
    matched_reporting_rules: list[RuleMatch]
    evidence: list[EvidenceItem]
