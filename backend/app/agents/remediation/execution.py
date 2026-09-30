"""The Remediation Agent - EXECUTION half. Nothing here is reachable by the LLM.

    human decision (API) -> approve | reject
    approve -> re-validate EVERYTHING against the current world -> kill switch -> ToolExecutor -> read back

Gates, in order (any failure = the action is NOT executed and the reason is recorded):
    proposal unchanged since approval (hash) -> approval is approved and not expired -> it is the incident's
    current plan -> not already executed (idempotency) -> KILL SWITCH (agent_actions_enabled) -> policy still
    allows the action / resource is not protected -> target still exists -> action still applicable (not
    already remediated) -> state unchanged since the plan was made (else stale_remediation_plan)
    -> ToolExecutor (permission + argument validation + exact-approval match) -> read the resource back and
    verify the post-condition (the tool's return message is not trusted).

The ToolExecutor receives the EXACT approved action / target / arguments, copied from the stored approval.
Cloud state is only ever changed by the ToolExecutor; this module never touches the simulator.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel

from app.agents.remediation import records
from app.agents.remediation.config import RemediationPolicy
from app.agents.remediation.state import (
    fingerprint,
    is_applicable,
    is_remediated,
    parse_target,
    read_state,
    safe_summary,
)
from app.database.connection import Database
from app.domain.agent_result import AgentAction, AgentResult
from app.domain.enums import AgentName, AgentRunStatus, ApprovalStatus, HumanActor, IncidentStatus
from app.domain.events import utcnow
from app.domain.incident import AuditEntry, IncidentState
from app.domain.remediation import (
    ApprovalState,
    ExecutionStatus,
    RemediationAction,
    RemediationAssessment,
    RemediationExecution,
)
from app.services.approvals import ApprovalService, ApprovalView
from app.services.incident_service import IncidentService
from app.tools.base import ApprovalGrant, ToolRequest
from app.tools.executor import ToolExecutor

logger = logging.getLogger(__name__)
AuditSink = Callable[[AuditEntry], None]
REVIEWER = HumanActor.ANALYST.value


class ApprovalNotFoundError(LookupError):
    pass


class ApprovalStateError(RuntimeError):
    """The approval is not in a state that allows the requested decision (already decided, expired...)."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class ApprovalReport(BaseModel):
    approval: ApprovalView
    outcome: str  # executed | rejected | actions_disabled | stale_remediation_plan | already_remediated | ...
    execution: RemediationExecution
    incident_status: IncidentStatus | None
    message: str
    agent_result: AgentResult


@dataclass
class _Gate:
    """A refusal to execute: `code` is machine-readable; `retryable` blocks keep the approval usable."""

    code: str
    message: str
    retryable: bool = False
    expire_approval: bool = False


class RemediationExecutor:
    def __init__(self, database: Database, policy: RemediationPolicy, tools: ToolExecutor,
                 audit_sink: AuditSink, clock: Callable[[], datetime] = utcnow) -> None:
        self._db = database
        self._policy = policy
        self._tools = tools
        self._audit = audit_sink
        self._clock = clock

    # ------------------------------------------------------------ public API
    def reject(self, approval_id: str, comment: str | None = None) -> ApprovalReport:
        now = self._clock()
        with self._db.session() as session:
            current = ApprovalService(session).get(approval_id, now)
        if current is None:
            raise ApprovalNotFoundError(f"approval '{approval_id}' not found")
        with self._db.session() as session:
            view = ApprovalService(session).transition(
                approval_id, ApprovalState.REJECTED, allowed_from=(ApprovalState.PENDING,), reviewed_by=REVIEWER,
                decision=comment or "rejected by the analyst", now=now)
        if view is None:
            raise ApprovalStateError(f"approval is {current.status.value}; only a pending approval can be rejected",
                                     current.status.value)
        execution = RemediationExecution(status=ExecutionStatus.REJECTED, action=RemediationAction(view.action),
                                         target=view.target, tool_name=view.action, approval_id=view.approval_id,
                                         reason_code="rejected", message="the analyst rejected the proposal")
        incident = self._update_incident(view, execution, IncidentStatus.REMEDIATION_REJECTED, now)
        self._audit(records.audit_entry(
            now, view.incident_id, "remediation.rejected", "rejected", f"{view.action} on {view.target} rejected",
            actor=HumanActor.ANALYST, run_id=view.agent_run_id, approval_id=view.approval_id, plan=self._plan(incident),
            execution_status=ExecutionStatus.REJECTED.value, reviewed_by=REVIEWER))
        return self._report(view, "rejected", execution, incident, AgentRunStatus.SUCCESS, "approval_rejected",
                            "The proposal was rejected. Nothing was executed.", now)

    def approve(self, approval_id: str, comment: str | None = None) -> ApprovalReport:
        """Approve the exact proposal, then try to execute it (all gates are re-checked)."""
        now = self._clock()
        with self._db.session() as session:
            current = ApprovalService(session).get(approval_id, now)
        if current is None:
            raise ApprovalNotFoundError(f"approval '{approval_id}' not found")
        if current.status == ApprovalState.EXPIRED:
            self._blocked(current, _Gate("approval_expired", "the approval request expired; run remediation again",
                                         expire_approval=True), now)
            raise ApprovalStateError("approval expired; a new remediation run is required", "approval_expired")
        with self._db.session() as session:
            view = ApprovalService(session).transition(
                approval_id, ApprovalState.APPROVED, allowed_from=(ApprovalState.PENDING,), reviewed_by=REVIEWER,
                decision=comment or "approved by the analyst", now=now)
        if view is None:
            raise ApprovalStateError(f"approval is {current.status.value}; only a pending approval can be approved",
                                     current.status.value)
        incident = self._update_incident(
            view, RemediationExecution(status=ExecutionStatus.APPROVED, action=RemediationAction(view.action),
                                       target=view.target, tool_name=view.action, approval_id=view.approval_id,
                                       message="approved by the analyst; execution has not happened yet"),
            IncidentStatus.REMEDIATION_APPROVED, now)
        self._audit(records.audit_entry(
            now, view.incident_id, "remediation.approved", "approved", f"{view.action} on {view.target} approved",
            actor=HumanActor.ANALYST, run_id=view.agent_run_id, approval_id=view.approval_id,
            plan=self._plan(incident), execution_status=ExecutionStatus.APPROVED.value, reviewed_by=REVIEWER))
        return self._execute(view, now)

    def execute(self, approval_id: str) -> ApprovalReport:
        """Execute an already-approved proposal (e.g. after the kill switch was enabled)."""
        now = self._clock()
        with self._db.session() as session:
            view = ApprovalService(session).get(approval_id, now)
        if view is None:
            raise ApprovalNotFoundError(f"approval '{approval_id}' not found")
        if view.status != ApprovalState.APPROVED:
            raise ApprovalStateError(f"approval is {view.status.value}; only an approved proposal can be executed",
                                     view.status.value)
        return self._execute(view, now)

    # --------------------------------------------------------------- pipeline
    def _execute(self, view: ApprovalView, now: datetime) -> ApprovalReport:
        incident = self._load(view.incident_id)
        gate = self._gates(view, incident)
        if isinstance(gate, _Gate):
            return self._blocked(view, gate, now, incident=incident)
        state_before, plan_fp = gate
        parsed = parse_target(view.target)
        assert parsed is not None
        resource_type, resource_id = parsed
        action_policy = self._policy.actions[view.action]
        before = safe_summary(resource_type, state_before)
        request = ToolRequest(
            tool_name=view.action, arguments=dict(view.arguments), requested_by=AgentName.REMEDIATION,
            incident_id=view.incident_id, reason=f"approved remediation {view.approval_id}",
            approval=ApprovalGrant(approval_id=view.approval_id, incident_id=view.incident_id, tool_name=view.action,
                                   status=ApprovalStatus.APPROVED, decided_by=view.reviewed_by or REVIEWER,
                                   arguments=dict(view.arguments)))
        result = self._tools.execute(request)  # the ONLY place that can change the cloud
        base = dict(action=RemediationAction(view.action), target=view.target, tool_name=view.action,
                    approval_id=view.approval_id, tool_request_id=result.request_id, before_state=before)
        if not result.ok:
            if result.error_code == "agent_actions_disabled":
                return self._blocked(view, _Gate("actions_disabled", "agent actions are disabled (kill switch)",
                                                 retryable=True), now, incident=incident)
            execution = RemediationExecution(status=ExecutionStatus.FAILED, reason_code=result.error_code or "tool_failed",
                                             message=(result.error or "the tool failed")[:300], **base)
            return self._finish(view, execution, now, IncidentStatus.REMEDIATION_FAILED, "remediation.failed",
                                "execution_failed", AgentRunStatus.FAILED, incident)
        after_state = read_state(self._tools, view.incident_id, resource_type, resource_id)
        after = safe_summary(resource_type, after_state) if after_state is not None else None
        if after_state is None or not is_remediated(after_state, action_policy):
            execution = RemediationExecution(
                status=ExecutionStatus.FAILED, reason_code="readback_mismatch", after_state=after,
                message="the tool reported success but the read-back state does not show the expected change", **base)
            return self._finish(view, execution, now, IncidentStatus.REMEDIATION_FAILED, "remediation.failed",
                                "readback_mismatch", AgentRunStatus.FAILED, incident)
        with self._db.session() as session:
            ApprovalService(session).mark_executed(view.approval_id, self._clock())
        execution = RemediationExecution(
            status=ExecutionStatus.EXECUTED, reason_code="executed", after_state=after, executed_at=self._clock(),
            message=f"{view.action} executed on {view.target}; the read-back state confirms the change", **base)
        return self._finish(view, execution, now, IncidentStatus.REMEDIATED, "remediation.executed", "action_executed",
                            AgentRunStatus.SUCCESS, incident)

    def _gates(self, view: ApprovalView, incident: IncidentState | None) -> _Gate | tuple[dict[str, Any], str]:
        if view.is_tampered:
            return _Gate("proposal_tampered", "the stored proposal no longer matches its approval hash", expire_approval=True)
        if view.status != ApprovalState.APPROVED:
            return _Gate("not_approved", f"approval is {view.status.value}")
        if incident is None or incident.remediation is None or incident.remediation.plan.proposal_hash != view.proposal_hash \
                or incident.remediation.approval is None or incident.remediation.approval.approval_id != view.approval_id:
            return _Gate("plan_mismatch", "this approval is not for the incident's current remediation plan; "
                                          "run remediation again", expire_approval=True)
        plan = incident.remediation.plan
        if (plan.action.value, plan.target, plan.arguments) != (view.action, view.target, view.arguments):
            return _Gate("plan_mismatch", "the plan differs from the approved proposal", expire_approval=True)
        if view.executed_at is not None or incident.remediation.execution.status == ExecutionStatus.EXECUTED:
            return _Gate("already_remediated", "this approved action was already executed; it will not run twice")
        if not self._tools.registry.agent_actions_enabled:
            return _Gate("actions_disabled", "agent actions are disabled (kill switch: AGENT_ACTIONS_ENABLED=false)",
                         retryable=True)
        policy = self._policy.actions.get(view.action)
        if policy is None or not policy.enabled:
            return _Gate("policy_blocked", f"action '{view.action}' is disabled by policy", expire_approval=True)
        if view.target in self._policy.protected_resources:
            return _Gate("policy_blocked", f"{view.target} is a protected resource", expire_approval=True)
        parsed = parse_target(view.target)
        if parsed is None or parsed[0] != policy.resource_type:
            return _Gate("invalid_target", f"'{view.target}' is not a valid target for {view.action}", expire_approval=True)
        state = read_state(self._tools, view.incident_id, *parsed)
        if state is None:
            return _Gate("invalid_target", f"{view.target} no longer exists", expire_approval=True)
        if is_remediated(state, policy):
            return _Gate("already_remediated", f"{view.target} is already in the desired state; nothing to do",
                         expire_approval=True)
        if not is_applicable(state, policy):
            return _Gate("stale_remediation_plan", "the action is no longer applicable to the current state; "
                                                   "run remediation again", expire_approval=True)
        if plan.state_fingerprint and fingerprint(state, policy.fingerprint_fields) != plan.state_fingerprint:
            return _Gate("stale_remediation_plan", f"the state of {view.target} changed after the plan was made; "
                                                   "run remediation again", expire_approval=True)
        return state, plan.state_fingerprint or ""

    # ----------------------------------------------------------------- outcomes
    def _blocked(self, view: ApprovalView, gate: _Gate, now: datetime,
                 incident: IncidentState | None = None) -> ApprovalReport:
        already = gate.code == "already_remediated" and incident is not None and incident.remediation is not None \
            and incident.remediation.execution.status == ExecutionStatus.EXECUTED
        if gate.expire_approval and not already:
            with self._db.session() as session:
                ApprovalService(session).transition(
                    view.approval_id, ApprovalState.EXPIRED, allowed_from=(ApprovalState.PENDING, ApprovalState.APPROVED),
                    reviewed_by="System", decision=gate.code, now=now)
        execution = RemediationExecution(
            status=ExecutionStatus.BLOCKED, action=RemediationAction(view.action), target=view.target,
            tool_name=view.action, approval_id=view.approval_id, reason_code=gate.code, message=gate.message)
        if already:  # nothing new happened: keep the recorded execution, only report and audit
            with self._db.session() as session:
                view = ApprovalService(session).get(view.approval_id, now) or view
            self._audit(records.audit_entry(
                now, view.incident_id, "remediation.blocked", "blocked", gate.message, run_id=view.agent_run_id,
                approval_id=view.approval_id, plan=self._plan(incident), reason_code=gate.code,
                execution_status=ExecutionStatus.BLOCKED.value))
            return self._report(view, gate.code, incident.remediation.execution, incident,  # type: ignore[union-attr]
                                AgentRunStatus.SKIPPED, gate.code, gate.message, now)
        status = IncidentStatus.REMEDIATION_APPROVED if gate.retryable else IncidentStatus.COMPLIANCE_ASSESSED
        incident = self._update_incident(view, execution, status, now, plan_incident=incident)
        with self._db.session() as session:
            view = ApprovalService(session).get(view.approval_id, now) or view
        self._audit(records.audit_entry(
            now, view.incident_id, "remediation.blocked", "blocked", gate.message, run_id=view.agent_run_id,
            approval_id=view.approval_id, plan=self._plan(incident), reason_code=gate.code,
            execution_status=ExecutionStatus.BLOCKED.value, errors=[gate.message]))
        return self._report(view, gate.code, execution, incident, AgentRunStatus.SKIPPED, gate.code, gate.message, now)

    def _finish(self, view: ApprovalView, execution: RemediationExecution, now: datetime, status: IncidentStatus,
                audit_action: str, outcome: str, run_status: AgentRunStatus, incident: IncidentState | None) -> ApprovalReport:
        incident = self._update_incident(view, execution, status, now, plan_incident=incident)
        with self._db.session() as session:
            view = ApprovalService(session).get(view.approval_id, now) or view
        self._audit(records.audit_entry(
            self._clock(), view.incident_id, audit_action, execution.status.value, execution.message,
            run_id=view.agent_run_id, approval_id=view.approval_id, plan=self._plan(incident),
            execution_status=execution.status.value, reason_code=execution.reason_code,
            before_state=execution.before_state, after_state=execution.after_state, tool_name=view.action,
            errors=[execution.message] if execution.status == ExecutionStatus.FAILED else None,
            reviewed_by=view.reviewed_by))
        return self._report(view, "executed" if execution.status == ExecutionStatus.EXECUTED else outcome,
                            execution, incident, run_status, outcome, execution.message, now)

    # ------------------------------------------------------------------ helpers
    def _load(self, incident_id: str) -> IncidentState | None:
        with self._db.session() as session:
            return IncidentService(session).get(incident_id)

    @staticmethod
    def _plan(incident: IncidentState | None):  # type: ignore[no-untyped-def]
        return incident.remediation.plan if incident and incident.remediation else None

    def _update_incident(self, view: ApprovalView, execution: RemediationExecution, status: IncidentStatus,
                         now: datetime, plan_incident: IncidentState | None = None) -> IncidentState | None:
        """Update incident.remediation only if `view` is the incident's CURRENT approval."""
        incident = plan_incident or self._load(view.incident_id)
        if incident is None or incident.remediation is None or incident.remediation.approval is None \
                or incident.remediation.approval.approval_id != view.approval_id:
            return incident
        with self._db.session() as session:
            fresh = ApprovalService(session).get(view.approval_id, now) or view
        keep = {"before_state": execution.before_state or incident.remediation.before_state,
                "after_state": execution.after_state or incident.remediation.after_state}
        # a blocked/failed retry must not erase a recorded before/after or an executed result
        assessment: RemediationAssessment = incident.remediation.model_copy(update={
            "status": execution.status, "execution": execution, "approval": records.approval_summary(fresh),
            "timestamp": incident.remediation.timestamp, **keep})
        stamp = AuditEntry(timestamp=now, incident_id=view.incident_id, actor=AgentName.REMEDIATION,
                           action="remediation.state_updated", decision=execution.status.value,
                           result=execution.message or execution.status.value,
                           details={"approval_id": view.approval_id, "execution_status": execution.status.value,
                                    "reason_code": execution.reason_code})
        return records.save_assessment(self._db, incident, assessment, status, stamp, now,
                                       f"{assessment.method.value}:{execution.status.value}", assessment.confidence)

    def _report(self, view: ApprovalView, outcome: str, execution: RemediationExecution,
                incident: IncidentState | None, status: AgentRunStatus, run_outcome: str, message: str,
                now: datetime) -> ApprovalReport:
        confidence = incident.remediation.confidence if incident and incident.remediation else 0.0
        result = AgentResult(
            agent_name=AgentName.REMEDIATION, incident_id=view.incident_id, status=status, outcome=run_outcome,
            confidence=confidence, reasoning_summary=message[:400],
            findings=[f"action:{view.action}", f"target:{view.target}", f"approval:{view.approval_id}",
                      f"execution:{execution.status.value}"],
            actions=[AgentAction(action="execute_action" if execution.status == ExecutionStatus.EXECUTED else "decide_approval",
                                 target=view.target, details={"tool": view.action, "approval_id": view.approval_id})],
            errors=[message] if status == AgentRunStatus.FAILED else [], timestamp=now)
        assessment = incident.remediation if incident else None
        records.record_run(self._db, run_id=f"RMA-{uuid4().hex[:10].upper()}", started=now, finished=self._clock(),
                           incident_id=view.incident_id, result=result,
                           method=assessment.method.value if assessment else None,
                           provider=assessment.provider if assessment else None,
                           model=assessment.model if assessment else None)
        return ApprovalReport(approval=view, outcome=outcome, execution=execution,
                              incident_status=incident.final_status if incident else None, message=message,
                              agent_result=result)
