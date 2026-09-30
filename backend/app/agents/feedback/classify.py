"""Deterministic outcome classification, failure analysis and recovery recommendations. Pure functions over
structured data already in the incident: no model, no I/O, no cloud access."""

from app.agents.feedback.config import FeedbackRules
from app.agents.verification.config import VerificationRules
from app.domain.incident import IncidentState
from app.domain.learning import FailureReason, FeedbackType, Recommendation
from app.domain.remediation import ExecutionStatus
from app.domain.verification import VerificationAssessment, VerificationStatus


def feedback_type_for(status: VerificationStatus, rules: FeedbackRules) -> FeedbackType:
    return rules.feedback_by_verification[status.value]


def analyze_failure(incident: IncidentState, v: VerificationAssessment,
                    verification_rules: VerificationRules) -> FailureReason | None:
    """Why did the response not achieve its effect? Uses only recorded facts; never asks a model."""
    if v.status == VerificationStatus.VERIFIED:
        return None
    if v.failure_reason == "remediation_execution_failed":
        return FailureReason.EXECUTION_FAILURE
    if v.status == VerificationStatus.UNKNOWN or v.failure_reason in ("state_unavailable", "state_incomplete"):
        return FailureReason.INSUFFICIENT_EVIDENCE
    target = v.target or ""
    affected = {f"{r.resource_type}/{r.resource_id}" for r in incident.affected_resources}
    if target and target not in affected:
        return FailureReason.WRONG_TARGET
    rule = verification_rules.verification.get(v.action.value)
    if rule is not None and target and target.split("/", 1)[0] != rule.resource_type:
        return FailureReason.WRONG_ACTION
    if v.status in (VerificationStatus.FAILED, VerificationStatus.PARTIAL):
        r = incident.remediation
        after = r.execution.after_state if r else None
        reported_ok = r is not None and r.execution.status == ExecutionStatus.EXECUTED
        if reported_ok and after is not None and v.expected_state and all(
                after.get(k) == val for k, val in v.expected_state.items()):
            return FailureReason.STATE_REGRESSION  # the remediation's own read-back was fine; it changed since
        return FailureReason.EXPECTED_STATE_NOT_REACHED
    return FailureReason.UNKNOWN


def recommend(feedback: FeedbackType, reason: FailureReason | None, retry_count: int,
              rules: FeedbackRules) -> Recommendation:
    """Recommendations only. Acting on one is always a separate, human-approved step."""
    if feedback == FeedbackType.SUCCESSFUL_RESPONSE:
        return rules.successful_response
    if feedback == FeedbackType.REGRESSION_DETECTED:
        return rules.recommend(rules.regression_detected, retry_count)
    if feedback == FeedbackType.PARTIAL_RESPONSE and reason in (None, FailureReason.EXPECTED_STATE_NOT_REACHED):
        return rules.recommend(rules.partial_response, retry_count)
    ladder = rules.recommendations[reason or FailureReason.UNKNOWN]
    return rules.recommend(ladder, retry_count)
