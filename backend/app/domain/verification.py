"""Verification models.

The Verification Agent answers one question: did the approved remediation achieve its intended security
effect? It never trusts the ToolExecutor's "success": it reads the resource's CURRENT state and compares

    BEFORE (recorded by the remediation)  ->  EXPECTED (config/verification_rules.yaml)  ->  ACTUAL (read now)

Everything here is backend-built and deterministic; no model can add evidence or change a status.
`VerificationMethod.LLM_ASSISTED` exists for a future interpretation step and is not used today.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.domain.events import utcnow
from app.domain.remediation import ExecutionStatus, RemediationAction


class VerificationStatus(str, Enum):
    VERIFIED = "verified"    # every expected state field holds now
    FAILED = "failed"        # none holds (or the remediation itself failed)
    PARTIAL = "partial"      # only some hold
    UNKNOWN = "unknown"      # the state could not be read / is incomplete: never converted to success
    SKIPPED = "skipped"      # nothing was executed, so there is nothing to verify (never stored on incidents)


class VerificationMethod(str, Enum):
    DETERMINISTIC = "deterministic"
    LLM_ASSISTED = "llm_assisted"  # reserved; the Verification Agent never calls an LLM today


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FieldComparison(_Strict):
    """One expected state field: what it was, what it should be, what it is."""

    field: str
    before: Any = None
    expected: Any
    actual: Any = None
    present: bool  # False if the field is missing from the current state (=> unknown, not success)
    satisfied: bool
    changed_from_before: bool


class VerificationEvidence(_Strict):
    """Backend-generated evidence (VER1, VER2, ...). Never model-authored."""

    evidence_id: str
    type: str  # before_state | expected_state | actual_state | execution_status | remediation_plan
    source: str
    description: str
    data: dict[str, Any] = Field(default_factory=dict)


class VerificationAssessment(_Strict):
    run_id: str
    status: VerificationStatus
    method: VerificationMethod = VerificationMethod.DETERMINISTIC
    action: RemediationAction
    target: str | None
    expected_effect: str
    expected_state: dict[str, Any]
    before_state: dict[str, Any] | None
    actual_state: dict[str, Any] | None
    comparison: list[FieldComparison]
    evidence: list[VerificationEvidence]
    confidence: float = Field(ge=0.0, le=1.0)  # computed by the verification logic, never copied
    reason: str
    failure_reason: str | None = None  # expected_state_not_achieved | remediation_execution_failed | state_unavailable ...
    reported_execution_status: ExecutionStatus | None = None  # what the remediation CLAIMED (not trusted)
    based_on_remediation_run: str | None = None
    approval_id: str | None = None
    recommendations: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utcnow)
