"""Remediation models.

RemediationDecision   - the strict contract the LLM (or rule-based fallback) must satisfy. It is only a
                        PROPOSAL: it can name one of the four allow-listed actions (or no_action), a target
                        and evidence ids. It carries no arguments, commands or code.
RemediationPlan       - the backend-validated plan: the exact action/target/tool arguments, the policy
                        that applies, and a fingerprint of the target's state when the plan was made.
RemediationExecution  - what actually happened (only the backend, through the ToolExecutor, can act).
RemediationAssessment - what is stored on the incident (`incident.remediation`).

Authority chain: model proposal -> backend validation -> policy -> human approval -> kill switch
-> ToolExecutor -> simulator. The model never executes anything.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.enums import Severity
from app.domain.events import utcnow
from app.domain.investigation import EvidenceItem

EvidenceId = str


class RemediationAction(str, Enum):
    """The only actions that exist. Each maps to exactly one registered ACTION tool."""

    DISABLE_ACCESS_KEY = "disable_access_key"
    REMOVE_ADMIN_PRIVILEGES = "remove_admin_privileges"
    ISOLATE_INSTANCE = "isolate_instance"
    MAKE_BUCKET_PRIVATE = "make_bucket_private"
    NO_ACTION = "no_action"


class RemediationMethod(str, Enum):
    LLM = "llm"
    RULE_BASED_FALLBACK = "rule_based_fallback"
    NO_CANDIDATES = "no_candidates"  # deterministic: the backend found nothing that could be proposed


class ExecutionStatus(str, Enum):
    NOT_EXECUTED = "not_executed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    EXECUTED = "executed"
    FAILED = "failed"


class ApprovalState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


def _lower(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ------------------------------------------------------------------ LLM output
class RemediationDecision(_Strict):
    action: RemediationAction
    target: str | None = Field(max_length=200)  # "IAMUser/alice"; null only for no_action
    reason: str = Field(min_length=10, max_length=400)
    evidence_ids: list[EvidenceId] = Field(max_length=12)
    expected_effect: str = Field(min_length=5, max_length=300)
    risk_level: Severity
    rollback_available: bool
    rollback_description: str = Field(min_length=3, max_length=300)
    requires_approval: bool
    confidence: float = Field(ge=0.0, le=1.0)
    unknowns: list[str] = Field(max_length=8)

    _action = field_validator("action", mode="before")(lambda v: _lower(v))
    _risk = field_validator("risk_level", mode="before")(lambda v: _lower(v))


# ------------------------------------------------------------- stored, backend-owned
class PolicyNote(_Strict):
    """A place where the backend policy replaced or refused something the model proposed."""

    field: str
    proposed: str
    final: str
    note: str


class RemediationPlan(_Strict):
    """The validated proposal. `arguments` are the exact ToolRequest arguments and are what the human
    approves; they are resolved by the backend from the target, never taken from the model."""

    plan_id: str
    action: RemediationAction
    tool_name: str | None = None
    target: str | None = None  # "IAMUser/alice"
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str
    evidence_ids: list[EvidenceId] = Field(default_factory=list)
    expected_effect: str
    risk: Severity
    proposed_risk: Severity
    requires_approval: bool = True
    rollback_available: bool = False
    rollback_description: str = ""
    policy_notes: list[PolicyNote] = Field(default_factory=list)
    state_fingerprint: str | None = None  # sha256 of the target's applicability state at plan time
    proposal_hash: str | None = None  # sha256 of (incident, action, target, arguments)
    excluded_actions: list[str] = Field(default_factory=list)  # candidates the policy refused, with why


class ApprovalSummary(_Strict):
    approval_id: str
    status: ApprovalState
    requested_at: datetime
    expires_at: datetime
    reviewed_at: datetime | None = None
    reviewed_by: str | None = None
    decision: str | None = None


class RemediationExecution(_Strict):
    status: ExecutionStatus = ExecutionStatus.NOT_EXECUTED
    action: RemediationAction | None = None
    target: str | None = None
    tool_name: str | None = None
    approval_id: str | None = None
    reason_code: str | None = None  # actions_disabled, stale_remediation_plan, already_remediated, ...
    message: str = ""
    before_state: dict[str, Any] | None = None
    after_state: dict[str, Any] | None = None
    tool_request_id: str | None = None
    executed_at: datetime | None = None


class RemediationAssessment(_Strict):
    run_id: str
    status: ExecutionStatus
    method: RemediationMethod
    provider: str
    model: str
    timestamp: datetime = Field(default_factory=utcnow)
    based_on_compliance_run: str | None = None
    input_event_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    plan: RemediationPlan
    approval: ApprovalSummary | None = None
    execution: RemediationExecution = Field(default_factory=RemediationExecution)
    before_state: dict[str, Any] | None = None
    after_state: dict[str, Any] | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
