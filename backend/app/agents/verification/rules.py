"""Prerequisites and expected-state lookup for verification."""

from dataclasses import dataclass
from typing import Any

from app.agents.remediation.state import parse_target
from app.agents.verification.config import ActionRule, VerificationRules
from app.domain.incident import IncidentState
from app.domain.remediation import ExecutionStatus, RemediationAction


@dataclass(frozen=True)
class Skip:
    """The remediation is not in a state that can be verified. Nothing is read, nothing is written."""

    outcome: str  # remediation_not_ready | remediation_not_executed
    message: str


NOT_READY = {ExecutionStatus.PENDING_APPROVAL, ExecutionStatus.APPROVED}
NOT_EXECUTED = {ExecutionStatus.REJECTED, ExecutionStatus.BLOCKED, ExecutionStatus.NOT_EXECUTED}


def check_ready(incident: IncidentState) -> Skip | None:
    r = incident.remediation
    if r is None:
        return Skip("remediation_not_ready", "the incident has no remediation; there is nothing to verify")
    if r.plan.action == RemediationAction.NO_ACTION:
        return Skip("remediation_not_executed", "the remediation proposed no action; there is nothing to verify")
    status = r.execution.status
    if status in NOT_READY:
        return Skip("remediation_not_ready", f"the remediation is {status.value.replace('_', ' ')}; it has not been executed")
    if status in NOT_EXECUTED:
        return Skip("remediation_not_executed", f"the remediation was {status.value.replace('_', ' ')}; nothing was executed")
    return None  # executed | failed


def rule_for(action: RemediationAction, rules: VerificationRules) -> ActionRule | None:
    return rules.verification.get(action.value)


def target_parts(target: str | None, rule: ActionRule) -> tuple[str, str] | None:
    parsed = parse_target(target)
    return parsed if parsed and parsed[0] == rule.resource_type else None


def expected_state(rule: ActionRule) -> dict[str, Any]:
    return dict(rule.required_state)
