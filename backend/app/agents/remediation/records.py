"""Shared bookkeeping for the Remediation Agent: audit entries, agent_runs rows and incident updates.

Audit entries never contain prompts, raw model output, credentials, secrets or reasoning traces; states
are the redacted summaries (no access-key ids)."""

import logging
from datetime import datetime
from typing import Any

from app.database.connection import Database
from app.database.models import AgentRunRecord
from app.domain.agent_result import AgentResult
from app.domain.enums import AgentName, ApprovalStatus, IncidentStatus, RemediationStatus
from app.domain.incident import Actor, AgentDecision, AuditEntry, IncidentState
from app.domain.remediation import (
    ApprovalSummary,
    ExecutionStatus,
    RemediationAction,
    RemediationAssessment,
    RemediationPlan,
)
from app.services.agent_runs import AgentRunService
from app.services.approvals import ApprovalView
from app.services.incident_service import IncidentService

logger = logging.getLogger(__name__)
AGENT = AgentName.REMEDIATION


def approval_summary(view: ApprovalView) -> ApprovalSummary:
    return ApprovalSummary(
        approval_id=view.approval_id, status=view.status, requested_at=view.requested_at,
        expires_at=view.expires_at, reviewed_at=view.reviewed_at, reviewed_by=view.reviewed_by,
        decision=view.decision)


def audit_entry(now: datetime, incident_id: str | None, action: str, decision: str, result: str, *,
                actor: Actor = AGENT, run_id: str | None = None, provider: str | None = None,
                model: str | None = None, method: str | None = None, plan: RemediationPlan | None = None,
                approval_id: str | None = None, execution_status: str | None = None,
                reason_code: str | None = None, before_state: dict[str, Any] | None = None,
                after_state: dict[str, Any] | None = None, errors: list[str] | None = None,
                confidence: float | None = None, reasoning: str = "", tool_name: str | None = None,
                reviewed_by: str | None = None) -> AuditEntry:
    details: dict[str, Any] = {
        "run_id": run_id, "agent": AGENT.value, "provider": provider, "model": model, "method": method,
        "action": plan.action.value if plan else None, "target": plan.target if plan else None,
        "approval_id": approval_id, "decision": decision, "execution_status": execution_status,
    }
    if plan is not None:
        details.update({"plan_id": plan.plan_id, "risk": plan.risk.value, "evidence_ids": plan.evidence_ids,
                        "policy_notes": [n.model_dump() for n in plan.policy_notes]})
    if reason_code:
        details["reason_code"] = reason_code
    if reviewed_by:
        details["reviewed_by"] = reviewed_by
    if before_state is not None:
        details["before_state"] = before_state
    if after_state is not None:
        details["after_state"] = after_state
    if errors:
        details["errors"] = [e[:300] for e in errors[:10]]
    return AuditEntry(timestamp=now, incident_id=incident_id, actor=actor, action=action, decision=decision,
                      result=result, reasoning=reasoning, confidence=confidence, tool_name=tool_name,
                      details=details)


def record_run(database: Database, *, run_id: str, started: datetime, finished: datetime, incident_id: str | None,
               result: AgentResult, method: str | None, provider: str | None, model: str | None) -> None:
    try:
        with database.session() as session:
            AgentRunService(session).record(AgentRunRecord(
                run_id=run_id, agent=AGENT.value, incident_id=incident_id, started_at=started,
                finished_at=finished, status=result.status.value, outcome=result.outcome, method=method,
                provider=provider, model=model, confidence=result.confidence,
                result=result.model_dump(mode="json", exclude={"evidence"})))
    except Exception:
        logger.exception("could not record remediation run %s", run_id)


_LEGACY_STATUS = {
    ExecutionStatus.PENDING_APPROVAL: (True, ApprovalStatus.PENDING, RemediationStatus.PROPOSED),
    ExecutionStatus.APPROVED: (True, ApprovalStatus.APPROVED, RemediationStatus.IN_PROGRESS),
    ExecutionStatus.REJECTED: (True, ApprovalStatus.REJECTED, RemediationStatus.SKIPPED),
    ExecutionStatus.EXECUTED: (True, ApprovalStatus.APPROVED, RemediationStatus.SUCCEEDED),
    ExecutionStatus.FAILED: (True, ApprovalStatus.APPROVED, RemediationStatus.FAILED),
    ExecutionStatus.BLOCKED: (True, ApprovalStatus.APPROVED, RemediationStatus.IN_PROGRESS),
}


def save_assessment(database: Database, incident: IncidentState, assessment: RemediationAssessment,
                    final_status: IncidentStatus | None, entry: AuditEntry, now: datetime,
                    decision_text: str, confidence: float) -> IncidentState:
    """Write `incident.remediation` (and lifecycle fields). Monitor, triage, investigation and compliance
    are never touched. `final_status=None` leaves the lifecycle status alone."""
    required, approval_status, legacy = _LEGACY_STATUS.get(
        assessment.status, (False, ApprovalStatus.NOT_REQUIRED, RemediationStatus.NOT_STARTED))
    if assessment.plan.action == RemediationAction.NO_ACTION:
        required, approval_status, legacy = False, ApprovalStatus.NOT_REQUIRED, RemediationStatus.SKIPPED
    updated = incident.model_copy(update={
        "remediation": assessment,
        "final_status": final_status or incident.final_status,
        "current_agent": AGENT,
        "approval_required": required, "approval_status": approval_status, "remediation_status": legacy,
        "agent_decisions": [x for x in incident.agent_decisions if x.actor != AGENT]
        + [AgentDecision(actor=AGENT, timestamp=now, confidence=confidence, decision=decision_text,
                         reasoning=assessment.summary)],
        "audit_log": incident.audit_log + [entry],
    })
    with database.session() as session:
        return IncidentService(session).save(updated)
