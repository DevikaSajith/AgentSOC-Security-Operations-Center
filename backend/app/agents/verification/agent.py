"""The Verification Agent (READ-ONLY, deterministic).

    incident -> prerequisites (remediation exists and was executed) -> read the target's CURRENT state
    (read tool, as the Verification Agent) -> compare BEFORE / EXPECTED / ACTUAL -> decision -> incident.verification
    -> audit -> AgentResult

It has no action-tool permission, no approval service, no LLM and no path to the simulator: it can only observe.
It never retries, approves or executes a remediation; a failed verification leaves the incident open with a
recommendation for a human (or a future orchestrator). Running it repeatedly is safe: it only re-reads state.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.agents.base import BaseAgent
from app.agents.verification.config import VerificationRules
from app.agents.verification.context import gather, read_current
from app.agents.verification.decision import decide
from app.agents.verification.rules import check_ready, rule_for, target_parts
from app.database.connection import Database
from app.database.models import AgentRunRecord
from app.domain.agent_result import AgentAction, AgentResult
from app.domain.enums import AgentName, AgentRunStatus, IncidentStatus, VerificationStatus as LegacyStatus
from app.domain.events import utcnow
from app.domain.incident import AgentDecision, AuditEntry, Evidence, IncidentState, VerificationResult
from app.domain.verification import VerificationAssessment, VerificationStatus
from app.services.agent_runs import AgentRunService
from app.services.incident_service import IncidentService
from app.tools.executor import ToolExecutor

logger = logging.getLogger(__name__)
AuditSink = Callable[[AuditEntry], None]

_PROGRESSABLE = {IncidentStatus.REMEDIATED, IncidentStatus.REMEDIATION_FAILED, IncidentStatus.VERIFIED,
                 IncidentStatus.VERIFICATION_FAILED, IncidentStatus.PARTIAL_REMEDIATION,
                 IncidentStatus.VERIFICATION_UNKNOWN}
_FINAL_STATUS = {VerificationStatus.VERIFIED: IncidentStatus.VERIFIED,
                 VerificationStatus.FAILED: IncidentStatus.VERIFICATION_FAILED,
                 VerificationStatus.PARTIAL: IncidentStatus.PARTIAL_REMEDIATION,
                 VerificationStatus.UNKNOWN: IncidentStatus.VERIFICATION_UNKNOWN}
_LEGACY = {VerificationStatus.VERIFIED: LegacyStatus.VERIFIED, VerificationStatus.FAILED: LegacyStatus.FAILED,
           VerificationStatus.PARTIAL: LegacyStatus.FAILED, VerificationStatus.UNKNOWN: LegacyStatus.NOT_VERIFIED}
_OUTCOME = {VerificationStatus.VERIFIED: "verified", VerificationStatus.FAILED: "verification_failed",
            VerificationStatus.PARTIAL: "verification_partial", VerificationStatus.UNKNOWN: "verification_unknown"}
_RUN_STATUS = {VerificationStatus.VERIFIED: AgentRunStatus.SUCCESS, VerificationStatus.FAILED: AgentRunStatus.SUCCESS,
               VerificationStatus.PARTIAL: AgentRunStatus.PARTIAL, VerificationStatus.UNKNOWN: AgentRunStatus.SUCCESS}


class VerificationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=36, pattern=r"^[A-Za-z0-9_-]+$")


class VerificationRunReport(BaseModel):
    run_id: str
    incident_id: str
    status: AgentRunStatus
    outcome: str
    verification_status: VerificationStatus | None
    validation_errors: list[str]
    verification: VerificationAssessment | None
    agent_result: AgentResult


@dataclass
class _Run:
    run_id: str
    now: datetime
    request: VerificationRunRequest
    incident: IncidentState | None = None
    status: AgentRunStatus = AgentRunStatus.FAILED
    outcome: str = ""
    errors: list[str] = field(default_factory=list)
    assessment: VerificationAssessment | None = None


class VerificationAgent(BaseAgent[VerificationRunRequest, VerificationRunReport]):
    name = AgentName.VERIFICATION

    def __init__(self, database: Database, rules: VerificationRules, tools: ToolExecutor | None,
                 audit_sink: AuditSink, clock: Callable[[], datetime] = utcnow) -> None:
        self._db = database
        self._rules = rules
        self._tools = tools
        self._audit = audit_sink
        self._clock = clock

    def run(self, request: VerificationRunRequest) -> VerificationRunReport:
        run = _Run(run_id=f"VER-{uuid4().hex[:10].upper()}", now=self._clock(), request=request)
        self._audit(self._entry(run, "verification.run", "started", "verification started"))
        try:
            with self._db.session() as session:
                run.incident = IncidentService(session).get(request.incident_id)
            if run.incident is None:
                run.outcome = "incident_not_found"
                run.errors.append(f"incident {request.incident_id} not found")
            else:
                skip = check_ready(run.incident)
                if skip is not None:
                    run.status, run.outcome = AgentRunStatus.SKIPPED, skip.outcome
                    run.errors.append(skip.message)
                else:
                    self._verify(run)
        except Exception as exc:  # report, never crash the caller
            logger.exception("verification run %s failed", run.run_id)
            run.status, run.outcome, run.assessment = AgentRunStatus.FAILED, "internal_error", None
            run.errors.append(f"internal_error:{type(exc).__name__}")
        result = self._result(run)
        self._record(run, result)
        return VerificationRunReport(
            run_id=run.run_id, incident_id=request.incident_id, status=result.status, outcome=run.outcome,
            verification_status=run.assessment.status if run.assessment else None, validation_errors=run.errors,
            verification=run.assessment, agent_result=result)

    # ------------------------------------------------------------------ stages
    def _verify(self, run: _Run) -> None:
        incident = run.incident
        assert incident is not None
        inputs = gather(incident)
        rule = rule_for(inputs.action, self._rules)
        assert rule is not None  # the config loader guarantees a rule for every action tool
        parts = target_parts(inputs.target, rule)
        raw = read_current(self._tools, incident.incident_id, parts) if parts else None
        assessment = decide(inputs, rule, self._rules, raw, run.run_id, run.now)
        run.assessment, run.status, run.outcome = assessment, _RUN_STATUS[assessment.status], _OUTCOME[assessment.status]
        action = "verification.completed" if assessment.status == VerificationStatus.VERIFIED else "verification.failed"
        entry = self._entry(run, action, assessment.status.value, assessment.reason, assessment=assessment)
        progress = incident.final_status in _PROGRESSABLE
        updated = incident.model_copy(update={
            "verification": assessment,
            "verification_result": VerificationResult(
                status=_LEGACY[assessment.status], checked_at=run.now, expected_state=assessment.expected_state,
                observed_state=assessment.actual_state or {}, details=assessment.reason[:500]),
            "final_status": _FINAL_STATUS[assessment.status] if progress else incident.final_status,
            "current_agent": AgentName.VERIFICATION if progress else incident.current_agent,
            # monitor / triage / investigation / compliance / remediation are intentionally left untouched
            "agent_decisions": [x for x in incident.agent_decisions if x.actor != AgentName.VERIFICATION]
            + [AgentDecision(actor=AgentName.VERIFICATION, timestamp=run.now, confidence=assessment.confidence,
                             decision=f"deterministic:{assessment.status.value}", reasoning=assessment.reason[:500])],
            "audit_log": incident.audit_log + [entry],
        })
        with self._db.session() as session:
            run.incident = IncidentService(session).save(updated)
        self._audit(entry)

    # ----------------------------------------------------------------- results
    def _result(self, run: _Run) -> AgentResult:
        incident_id, a = run.request.incident_id, run.assessment
        if a is None:
            return AgentResult(agent_name=self.name, incident_id=incident_id, status=run.status, outcome=run.outcome,
                               confidence=0.0, reasoning_summary="Nothing was verified; the incident and the cloud are unchanged.",
                               errors=run.errors or [run.outcome])
        return AgentResult(
            agent_name=self.name, incident_id=incident_id, status=run.status, outcome=run.outcome,
            confidence=a.confidence, reasoning_summary=a.reason[:500],
            findings=[f"status:{a.status.value}", f"method:{a.method.value}", f"action:{a.action.value}",
                      f"target:{a.target}", f"reported_execution:{a.reported_execution_status.value if a.reported_execution_status else 'none'}"]
            + [f"{c.field}:before={c.before}:expected={c.expected}:actual={c.actual}:{'ok' if c.satisfied else 'not_met'}"
               for c in a.comparison] + ([f"failure:{a.failure_reason}"] if a.failure_reason else []),
            evidence=[Evidence(kind=e.type, description=e.description, data=e.data, collected_by=self.name,
                               collected_at=run.now) for e in a.evidence],
            actions=[AgentAction(action="update_incident", target=incident_id,
                                 details={"fields": ["verification", "verification_result", "final_status", "current_agent"]})],
            recommendations=a.recommendations, errors=[] if a.status == VerificationStatus.VERIFIED else [a.reason[:300]],
            timestamp=run.now)

    def _entry(self, run: _Run, action: str, decision: str, result: str,
               assessment: VerificationAssessment | None = None) -> AuditEntry:
        details: dict[str, Any] = {"run_id": run.run_id, "agent": self.name.value, "method": "deterministic"}
        if assessment is not None:
            details.update({
                "verification_status": assessment.status.value, "action": assessment.action.value,
                "target": assessment.target, "expected_effect": assessment.expected_effect,
                "expected_state": assessment.expected_state, "actual_state": assessment.actual_state,
                "confidence": assessment.confidence, "failure_reason": assessment.failure_reason,
                "reported_execution_status": assessment.reported_execution_status.value
                if assessment.reported_execution_status else None})
        if run.errors:
            details["errors"] = [e[:300] for e in run.errors[:10]]
        return AuditEntry(timestamp=self._clock(), incident_id=run.request.incident_id, actor=self.name, action=action,
                          decision=decision, result=result[:500], reasoning="",
                          confidence=assessment.confidence if assessment else None, details=details)

    def _record(self, run: _Run, result: AgentResult) -> None:
        if run.assessment is None:
            self._audit(self._entry(run, "verification.skipped" if result.status == AgentRunStatus.SKIPPED
                                    else "verification.failed", result.status.value, run.outcome))
        try:
            with self._db.session() as session:
                AgentRunService(session).record(AgentRunRecord(
                    run_id=run.run_id, agent=self.name.value, incident_id=run.request.incident_id,
                    started_at=run.now, finished_at=self._clock(), status=result.status.value,
                    outcome=run.outcome, method="deterministic", provider=None, model=None,
                    confidence=result.confidence, result=result.model_dump(mode="json", exclude={"evidence"})))
        except Exception:
            logger.exception("could not record verification run %s", run.run_id)
