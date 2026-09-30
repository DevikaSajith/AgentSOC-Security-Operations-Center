"""The verification decision: deterministic, config-driven, no model. Confidence comes from the KIND of result
(config/verification_rules.yaml), never from another agent."""

from datetime import datetime
from typing import Any

from app.agents.remediation.state import safe_summary
from app.agents.verification.comparison import classify, compare
from app.agents.verification.config import ActionRule, VerificationRules
from app.agents.verification.context import VerificationInputs
from app.domain.remediation import ExecutionStatus
from app.domain.verification import (
    FieldComparison,
    VerificationAssessment,
    VerificationEvidence,
    VerificationMethod,
    VerificationStatus,
)

RECOMMENDATIONS = {
    VerificationStatus.VERIFIED: ["close_incident_after_human_review"],
    VerificationStatus.FAILED: ["reassess_remediation", "keep_incident_open"],
    VerificationStatus.PARTIAL: ["reassess_remediation", "review_remaining_exposure", "keep_incident_open"],
    VerificationStatus.UNKNOWN: ["restore_state_visibility", "re_run_verification", "keep_incident_open"],
}


def _evidence(inputs: VerificationInputs, expected: dict[str, Any], actual: dict[str, Any] | None) -> list[VerificationEvidence]:
    items = [
        VerificationEvidence(evidence_id="VER1", type="before_state", source="Remediation Agent (recorded)",
                             description="State of the target before the remediation, as recorded by it.",
                             data=dict(inputs.before_state or {})),
        VerificationEvidence(evidence_id="VER2", type="expected_state", source="verification_rules.yaml",
                             description=f"State the target must be in after {inputs.action.value}.", data=dict(expected)),
        VerificationEvidence(evidence_id="VER3", type="actual_state", source="Simulated cloud (read now via get_resource)",
                             description="Current state of the target." if actual is not None else "The current state could not be read.",
                             data=dict(actual or {})),
        VerificationEvidence(evidence_id="VER4", type="execution_status", source="Remediation Agent (claimed, NOT trusted)",
                             description=f"The remediation reports execution status '{inputs.reported_status.value}'.",
                             data={"execution_status": inputs.reported_status.value, "approval_id": inputs.approval_id}),
    ]
    return items


def _describe(rows: list[FieldComparison]) -> str:
    return "; ".join(f"{r.field}: expected {r.expected}, actual {r.actual}" for r in rows)


def decide(inputs: VerificationInputs, rule: ActionRule, rules: VerificationRules, raw_actual: dict[str, Any] | None,
           run_id: str, now: datetime) -> VerificationAssessment:
    expected = dict(rule.required_state)
    resource_type = rule.resource_type
    actual = safe_summary(resource_type, raw_actual) if raw_actual is not None else None
    # compare on the raw (unredacted) state so every configured field is present; only the summary is stored
    rows = compare(inputs.before_state, expected, raw_actual) if raw_actual is not None else []
    conf = rules.confidence
    failure: str | None = None
    if raw_actual is None:
        status, confidence = VerificationStatus.UNKNOWN, conf.unknown
        failure = "state_unavailable"
        reason = "The target's current state could not be read (resource missing or unreadable); the result is unknown."
    else:
        status = classify(rows)
        if status == VerificationStatus.UNKNOWN:
            confidence, failure = conf.unknown, "state_incomplete"
            reason = "The current state does not contain every expected field: " + _describe(rows)
        elif status == VerificationStatus.VERIFIED:
            confidence = conf.verified
            reason = f"The remediation achieved its expected security effect: {rule.description}."
        elif status == VerificationStatus.PARTIAL:
            confidence, failure = conf.partial, "expected_state_partially_achieved"
            reason = "Only part of the expected state was achieved: " + _describe([r for r in rows if not r.satisfied])
        else:
            confidence, failure = conf.failed, "expected_state_not_achieved"
            reason = "The intended security state was not achieved: " + _describe(rows)
    if inputs.reported_status == ExecutionStatus.FAILED:
        # the remediation itself failed: never present it as a success, whatever the state happens to be now
        status, failure = VerificationStatus.FAILED, "remediation_execution_failed"
        confidence = conf.execution_failed
        reason = "The remediation execution failed" + (
            f"; current state: {_describe(rows)}" if rows else "; the current state could not be read") + "."
    return VerificationAssessment(
        run_id=run_id, status=status, method=VerificationMethod.DETERMINISTIC, action=inputs.action, target=inputs.target,
        expected_effect=inputs.expected_effect, expected_state=expected, before_state=inputs.before_state,
        actual_state=actual, comparison=rows, evidence=_evidence(inputs, expected, actual), confidence=confidence,
        reason=reason, failure_reason=failure, reported_execution_status=inputs.reported_status,
        based_on_remediation_run=inputs.remediation_run, approval_id=inputs.approval_id,
        recommendations=RECOMMENDATIONS[status], timestamp=now)
