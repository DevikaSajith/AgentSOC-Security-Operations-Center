"""What the verification needs: the recorded remediation (reused as-is from Phase 6) plus the resource's
CURRENT state, read through the read tool `get_resource` as the Verification Agent (read-only permissions)."""

from dataclasses import dataclass
from typing import Any

from app.agents.remediation.state import read_state
from app.domain.enums import AgentName
from app.domain.incident import IncidentState
from app.domain.remediation import ExecutionStatus, RemediationAction
from app.tools.executor import ToolExecutor


@dataclass
class VerificationInputs:
    action: RemediationAction
    target: str | None
    expected_effect: str
    before_state: dict[str, Any] | None  # the redacted before-state the remediation recorded
    reported_status: ExecutionStatus  # what the remediation CLAIMS happened (never trusted)
    approval_id: str | None
    remediation_run: str
    plan_id: str


def gather(incident: IncidentState) -> VerificationInputs:
    r = incident.remediation
    assert r is not None
    return VerificationInputs(
        action=r.plan.action, target=r.plan.target, expected_effect=r.plan.expected_effect,
        before_state=r.execution.before_state or r.before_state, reported_status=r.execution.status,
        approval_id=r.execution.approval_id or (r.approval.approval_id if r.approval else None),
        remediation_run=r.run_id, plan_id=r.plan.plan_id)


def read_current(tools: ToolExecutor | None, incident_id: str, resource: tuple[str, str]) -> dict[str, Any] | None:
    """The resource's current raw state, or None if it is missing / unreadable. Read-only."""
    return read_state(tools, incident_id, resource[0], resource[1], actor=AgentName.VERIFICATION)
