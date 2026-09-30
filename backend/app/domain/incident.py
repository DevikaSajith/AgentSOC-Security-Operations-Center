"""IncidentState: the single record every agent reads from and writes to.

Agents are not implemented in this phase. These models define the contract they will
share, so an incident can move Monitor -> Triage -> Investigator -> Compliance ->
Remediation while keeping one typed, auditable state.
"""

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from app.domain.enums import (
    AgentName,
    ApprovalStatus,
    EventSource,
    HumanActor,
    IncidentCategory,
    IncidentStatus,
    Priority,
    RemediationStatus,
    Severity,
    VerificationStatus,
)
from app.domain.events import DEFAULT_REGION, SIMULATED_ACCOUNT_ID, utcnow
from app.domain.compliance import ComplianceAssessment
from app.domain.ml import MLPrediction
from app.domain.remediation import RemediationAssessment
from app.domain.verification import VerificationAssessment
from app.domain.investigation import InvestigationAssessment
from app.domain.triage import TriageAssessment

Confidence = float  # always 0.0 - 1.0; enforced with Field(ge=0, le=1) where used
Actor = AgentName | HumanActor


def new_incident_id() -> str:
    """INC-XXXXXXXX (random, collision-safe for this project's scale)."""
    return f"INC-{uuid4().hex[:8].upper()}"


class AffectedResource(BaseModel):
    """A cloud resource involved in an attack or incident."""

    resource_type: str
    resource_id: str


class Evidence(BaseModel):
    """A piece of evidence supporting a finding (usually a stored event)."""

    evidence_id: str = Field(default_factory=lambda: f"EVD-{uuid4().hex[:8].upper()}")
    kind: str = Field(min_length=1)  # "event", "cloud_state", "policy", ...
    description: str
    event_id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    collected_by: Actor | None = None
    collected_at: datetime = Field(default_factory=utcnow)


class MitreTechnique(BaseModel):
    """A MITRE ATT&CK technique linked to an incident."""

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactic: str
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)


class RemediationStep(BaseModel):
    """One allow-listed action in a remediation plan (executed only via the tool layer)."""

    step_id: str = Field(default_factory=lambda: f"STEP-{uuid4().hex[:6].upper()}")
    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    reversible: bool = True
    status: RemediationStatus = RemediationStatus.PROPOSED
    result: dict[str, Any] | None = None


class RemediationPlan(BaseModel):
    """The ordered actions proposed to contain an incident."""

    plan_id: str = Field(default_factory=lambda: f"PLAN-{uuid4().hex[:6].upper()}")
    steps: list[RemediationStep] = Field(default_factory=list)
    proposed_by: Actor = AgentName.REMEDIATION
    risk: Severity = Severity.MEDIUM
    created_at: datetime = Field(default_factory=utcnow)


class VerificationResult(BaseModel):
    """Whether cloud state confirms the remediation worked."""

    status: VerificationStatus = VerificationStatus.NOT_VERIFIED
    checked_at: datetime | None = None
    expected_state: dict[str, Any] = Field(default_factory=dict)
    observed_state: dict[str, Any] = Field(default_factory=dict)
    details: str = ""


class AgentDecision(BaseModel):
    """A decision taken by an agent (or a human) while handling an incident."""

    decision_id: str = Field(default_factory=lambda: f"DEC-{uuid4().hex[:8].upper()}")
    actor: Actor
    decision: str = Field(min_length=1)  # e.g. "escalate", "close_as_false_positive"
    reasoning: str = ""
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=utcnow)


class AuditEntry(BaseModel):
    """An immutable audit record. Everything that changes state produces one."""

    audit_id: str = Field(default_factory=lambda: f"AUD-{uuid4().hex[:10].upper()}")
    timestamp: datetime = Field(default_factory=utcnow)
    incident_id: str | None = None
    actor: Actor
    action: str = Field(min_length=1)
    decision: str = ""
    result: str = ""
    reasoning: str = ""
    confidence: Confidence | None = Field(default=None, ge=0.0, le=1.0)
    tool_name: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class IncidentState(BaseModel):
    """Complete, typed state of one incident across the whole agent pipeline."""

    # --- identity / origin (set by the Monitor Agent)
    incident_id: str = Field(default_factory=new_incident_id)
    timestamp: datetime = Field(default_factory=utcnow)  # when the incident was opened
    updated_at: datetime = Field(default_factory=utcnow)
    title: str = Field(min_length=1)
    description: str = ""
    source: EventSource
    event_type: str
    account_id: str = SIMULATED_ACCOUNT_ID
    region: str = DEFAULT_REGION
    resource_id: str | None = None
    principal_id: str | None = None
    source_ip: str | None = None
    raw_event: dict[str, Any] = Field(default_factory=dict)
    normalized_event: dict[str, Any] = Field(default_factory=dict)
    related_event_ids: list[str] = Field(default_factory=list)

    # --- triage
    severity: Severity = Severity.INFO
    priority: Priority | None = None
    category: IncidentCategory = IncidentCategory.OTHER
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)

    # --- ML threat prediction (decision support from the Monitor stage; NOT the incident confidence)
    ml_prediction: MLPrediction | None = None

    # --- triage (latest valid assessment; severity/priority/category/confidence above
    #     are updated from it, and triage.previous keeps the Monitor's initial values)
    triage: TriageAssessment | None = None

    # --- investigation
    affected_resources: list[AffectedResource] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    investigation: InvestigationAssessment | None = None  # latest valid investigation
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)

    # --- compliance
    compliance: ComplianceAssessment | None = None  # latest valid compliance assessment

    # --- remediation (latest validated proposal + approval + execution)
    remediation: RemediationAssessment | None = None

    # --- verification (independent read-back of the cloud after remediation)
    verification: VerificationAssessment | None = None

    # --- legacy placeholders (unused by the Remediation Agent; kept for stored-data compatibility)
    remediation_plan: RemediationPlan | None = None
    remediation_status: RemediationStatus = RemediationStatus.NOT_STARTED
    approval_required: bool = False
    approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED
    verification_result: VerificationResult | None = None

    # --- traceability
    current_agent: AgentName | None = None
    agent_decisions: list[AgentDecision] = Field(default_factory=list)
    audit_log: list[AuditEntry] = Field(default_factory=list)
    final_status: IncidentStatus = IncidentStatus.NEW

    @model_validator(mode="after")
    def _approval_consistency(self) -> "IncidentState":
        """An approval gate cannot be 'not required' and pending/decided at once."""
        if self.approval_required and self.approval_status == ApprovalStatus.NOT_REQUIRED:
            raise ValueError("approval_required is true but approval_status is 'not_required'")
        if not self.approval_required and self.approval_status != ApprovalStatus.NOT_REQUIRED:
            raise ValueError(
                f"approval_status is '{self.approval_status.value}' but approval_required is false")
        return self
