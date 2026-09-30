"""The Remediation Agent - PLANNING half (the LLM proposes, the backend disposes).

    compliance-assessed incident -> gate -> deterministic analysis (affected resources, current cloud state,
    policy, candidate actions) -> bounded context -> LLM (text only) -> RemediationDecision ->
    action / target / evidence / policy validation (one repair) -> RemediationPlan (backend resolves the exact
    tool arguments, risk and approval need) -> approval REQUEST -> incident.remediation -> audit -> AgentResult

Running this agent NEVER executes anything and never changes the cloud. Execution happens only through
`RemediationExecutor` (execution.py) after a human approves, behind the kill switch, via the ToolExecutor.
The model has no tools, no execution authority and no way to name arguments.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.agents.base import BaseAgent
from app.agents.remediation import records
from app.agents.remediation.config import RemediationPolicy
from app.agents.remediation.context import RemediationContext, RemediationContextBuilder
from app.agents.remediation.fallback import rule_based_decision
from app.agents.remediation.prompts import SYSTEM_PROMPT, build_repair_prompt, build_user_prompt
from app.agents.remediation.validation import finalize, validate_decision
from app.agents.structured import DecisionValidationError, ask_structured
from app.database.connection import Database
from app.domain.agent_result import AgentAction, AgentResult, ProposedAction
from app.domain.enums import AgentName, AgentRunStatus, IncidentStatus
from app.domain.events import utcnow
from app.domain.incident import AuditEntry, Evidence, IncidentState
from app.domain.remediation import (
    ExecutionStatus,
    RemediationAction,
    RemediationAssessment,
    RemediationDecision,
    RemediationExecution,
    RemediationMethod,
    RemediationPlan,
)
from app.llm.base import LLMProvider
from app.services.approvals import ApprovalService, ApprovalView
from app.services.incident_service import IncidentService
from app.tools.executor import ToolExecutor

logger = logging.getLogger(__name__)

AuditSink = Callable[[AuditEntry], None]
_PROGRESSABLE = {IncidentStatus.COMPLIANCE_ASSESSED, IncidentStatus.REMEDIATION_PENDING,
                 IncidentStatus.REMEDIATION_APPROVED, IncidentStatus.REMEDIATION_REJECTED,
                 IncidentStatus.REMEDIATION_FAILED, IncidentStatus.REMEDIATED, IncidentStatus.VERIFIED,
                 IncidentStatus.VERIFICATION_FAILED, IncidentStatus.PARTIAL_REMEDIATION,
                 IncidentStatus.VERIFICATION_UNKNOWN}
DECISION_SCHEMA = RemediationDecision.model_json_schema()


class RemediationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=36, pattern=r"^[A-Za-z0-9_-]+$")
    allow_rule_based_fallback: bool = Field(
        default=False, description="If no valid LLM decision is obtained, use the deterministic "
                                   "rule_based_fallback (clearly labelled). It still needs policy validation, "
                                   "human approval and the kill switch.")


class RemediationRunReport(BaseModel):
    run_id: str
    incident_id: str
    status: AgentRunStatus
    outcome: str
    method: RemediationMethod | None
    provider: str | None
    model: str | None
    attempts: int
    validation_errors: list[str]
    remediation: RemediationAssessment | None
    approval: ApprovalView | None
    agent_result: AgentResult


@dataclass
class _Run:
    run_id: str
    now: datetime
    request: RemediationRunRequest
    incident: IncidentState | None = None
    context: RemediationContext | None = None
    decision: RemediationDecision | None = None
    plan: RemediationPlan | None = None
    method: RemediationMethod | None = None
    attempts: int = 0
    errors: list[str] = field(default_factory=list)
    outcome: str = ""
    status: AgentRunStatus = AgentRunStatus.FAILED
    approval: ApprovalView | None = None


class RemediationAgent(BaseAgent[RemediationRunRequest, RemediationRunReport]):
    name = AgentName.REMEDIATION

    def __init__(self, database: Database, policy: RemediationPolicy, provider: LLMProvider | None,
                 tools: ToolExecutor | None, audit_sink: AuditSink,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self._db = database
        self._policy = policy
        self._provider = provider
        self._tools = tools
        self._audit = audit_sink
        self._clock = clock

    @property
    def provider_name(self) -> str | None:
        return self._provider.name if self._provider else None

    @property
    def model_name(self) -> str | None:
        return self._provider.model if self._provider else None

    # --------------------------------------------------------------------- run
    def run(self, request: RemediationRunRequest) -> RemediationRunReport:
        run = _Run(run_id=f"RMD-{uuid4().hex[:10].upper()}", now=self._clock(), request=request)
        self._audit(self._entry(run, "remediation.run", "started", "remediation planning started"))
        assessment: RemediationAssessment | None = None
        try:
            with self._db.session() as session:
                run.incident = IncidentService(session).get(request.incident_id)
            if run.incident is None:
                run.outcome = "incident_not_found"
                run.errors.append(f"incident {request.incident_id} not found")
            elif run.incident.compliance is None or run.incident.investigation is None:
                run.status, run.outcome = AgentRunStatus.SKIPPED, "compliance_required"
                run.errors.append("the incident has no compliance assessment; run the Compliance Agent first")
            elif run.incident.compliance.based_on_investigation_run != run.incident.investigation.run_id:
                run.status, run.outcome = AgentRunStatus.SKIPPED, "compliance_required"
                run.errors.append("the compliance assessment predates the latest investigation; re-run the "
                                  "Compliance Agent first (it is not run automatically)")
            elif run.incident.final_status not in _PROGRESSABLE:
                run.status, run.outcome = AgentRunStatus.SKIPPED, "incident_not_remediable"
                run.errors.append(f"incident status '{run.incident.final_status.value}' does not allow remediation")
            else:
                run.context = RemediationContextBuilder(self._policy, self._tools).build(run.incident)
                assessment = self._plan(run)
        except Exception as exc:  # report, never crash the caller
            logger.exception("remediation run %s failed", run.run_id)
            run.status, run.outcome, assessment = AgentRunStatus.FAILED, "internal_error", None
            run.errors.append(f"internal_error:{type(exc).__name__}")
        result = self._result(run, assessment)
        self._record(run, result)
        return RemediationRunReport(
            run_id=run.run_id, incident_id=request.incident_id, status=result.status, outcome=run.outcome,
            method=run.method, provider=self.provider_name, model=self.model_name, attempts=run.attempts,
            validation_errors=run.errors, remediation=assessment, approval=run.approval, agent_result=result)

    # ------------------------------------------------------------------ stages
    def _plan(self, run: _Run) -> RemediationAssessment | None:
        assert run.context is not None and run.incident is not None
        analysis = run.context.analysis
        previous = run.incident.remediation
        if not analysis.candidates:
            if previous is not None and previous.execution.status == ExecutionStatus.EXECUTED:
                run.status, run.outcome = AgentRunStatus.SKIPPED, "already_remediated"
                run.errors.append("the proposed action was already executed and the target is in the desired "
                                  "state; nothing to do")
                return None
            run.method = RemediationMethod.NO_CANDIDATES
            run.decision = rule_based_decision(run.context, self._policy)  # deterministic no_action
        else:
            self._decide(run)
            if run.decision is None:
                return None
        run.plan = finalize(run.decision, run.context, self._policy, run.request.incident_id)
        run.status = AgentRunStatus.SUCCESS
        if run.plan.action == RemediationAction.NO_ACTION:
            run.outcome = "no_action"
            return self._apply_no_action(run)
        run.outcome = ("remediation_proposed" if run.method == RemediationMethod.LLM
                       else "remediation_proposed_rule_based_fallback")
        return self._apply_proposal(run)

    def _decide(self, run: _Run) -> None:
        assert run.context is not None
        context, policy = run.context, self._policy
        context_json = context.to_json()
        result = ask_structured(
            self._provider, SYSTEM_PROMPT, build_user_prompt(context_json), DECISION_SCHEMA,
            validate=lambda text: validate_decision(text, context, policy),
            repair=lambda previous, problems: build_repair_prompt(
                context_json, previous, problems, sorted(context.analysis.observed_ids() & context.evidence_ids)),
            max_repairs=policy.policy.max_repair_attempts)
        run.attempts, run.errors = result.attempts, run.errors + result.errors
        if result.value is not None:
            run.decision, run.method = result.value, RemediationMethod.LLM
        elif run.request.allow_rule_based_fallback:
            decision = rule_based_decision(context, policy)
            try:  # the fallback goes through the same validation as the model's answer
                run.decision = validate_decision(decision.model_dump_json(), context, policy)
                run.method = RemediationMethod.RULE_BASED_FALLBACK
            except DecisionValidationError as exc:
                run.errors.extend(f"fallback {exc.code}: {p}" for p in exc.problems[:5])
                run.outcome = "invalid_llm_output"
        else:
            run.outcome = result.failure  # nothing is stored, no approval is created

    def _assessment(self, run: _Run, status: ExecutionStatus) -> RemediationAssessment:
        assert run.decision and run.plan and run.context and run.incident and run.incident.compliance
        analysis, method = run.context.analysis, run.method
        assert method is not None
        llm = method == RemediationMethod.LLM
        unknowns = list(dict.fromkeys(run.decision.unknowns))
        if run.plan.action == RemediationAction.NO_ACTION and run.plan.excluded_actions:
            unknowns += [f"Not proposed: {x}" for x in run.plan.excluded_actions[:6]]
        cited = set(run.plan.evidence_ids)
        return RemediationAssessment(
            run_id=run.run_id, status=status, method=method,
            provider=self.provider_name if llm else "rule_based",
            model=self.model_name if llm else "remediation_policy.yaml", timestamp=run.now,
            based_on_compliance_run=run.incident.compliance.run_id, input_event_ids=analysis.event_ids,
            confidence=run.decision.confidence, summary=run.plan.reason, plan=run.plan,
            evidence=[e for i, e in analysis.evidence.items() if i in cited],
            unknowns=unknowns,
            recommendations=[f"human_review_of:{run.plan.action.value}"] if run.plan.action != RemediationAction.NO_ACTION
            else ["human_review_recommended"],
            before_state=self._before_state(run), execution=RemediationExecution(
                status=status, action=run.plan.action if run.plan.action != RemediationAction.NO_ACTION else None,
                target=run.plan.target, tool_name=run.plan.tool_name))

    @staticmethod
    def _before_state(run: _Run) -> dict[str, Any] | None:
        assert run.context and run.plan
        candidate = run.context.analysis.find(run.plan.action, run.plan.target)
        return dict(candidate.state) if candidate else None

    def _apply_no_action(self, run: _Run) -> RemediationAssessment:
        assert run.incident and run.plan
        assessment = self._assessment(run, ExecutionStatus.NOT_EXECUTED)
        entry = self._entry(run, "remediation.proposed", "no_action", "no remediation action proposed",
                            plan=run.plan, execution_status=ExecutionStatus.NOT_EXECUTED.value)
        progress = run.incident.final_status in {IncidentStatus.REMEDIATION_PENDING, IncidentStatus.REMEDIATION_REJECTED,
                                                 IncidentStatus.REMEDIATION_FAILED}
        with self._db.session() as session:  # a previous open approval for this incident is now moot
            ApprovalService(session).supersede_pending(run.request.incident_id, self._clock())
        run.incident = records.save_assessment(
            self._db, run.incident, assessment, IncidentStatus.COMPLIANCE_ASSESSED if progress else None,
            entry, run.now, f"{run.method.value}:no_action", assessment.confidence)  # type: ignore[union-attr]
        self._audit(entry)
        return assessment

    def _apply_proposal(self, run: _Run) -> RemediationAssessment:
        assert run.incident and run.plan and run.plan.target and run.plan.proposal_hash
        plan, now = run.plan, self._clock()
        with self._db.session() as session:
            service = ApprovalService(session)
            service.supersede_pending(run.request.incident_id, now)
            run.approval = service.create(
                incident_id=run.request.incident_id, agent_run_id=run.run_id, action=plan.action.value,
                target=plan.target, arguments=plan.arguments, reason=plan.reason, risk=plan.risk.value,
                evidence_ids=plan.evidence_ids, expected_effect=plan.expected_effect, requested_at=now,
                expires_at=now + timedelta(minutes=self._policy.approval.ttl_minutes))
        assessment = self._assessment(run, ExecutionStatus.PENDING_APPROVAL)
        assessment = assessment.model_copy(update={"approval": records.approval_summary(run.approval)})
        proposed = self._entry(run, "remediation.proposed", "proposed",
                               f"{plan.action.value} on {plan.target} proposed (risk {plan.risk.value})",
                               plan=plan, execution_status=ExecutionStatus.PENDING_APPROVAL.value,
                               approval_id=run.approval.approval_id, confidence=assessment.confidence,
                               reasoning=plan.reason)
        requested = self._entry(run, "remediation.approval_requested", "pending",
                                f"human approval requested for {plan.action.value} on {plan.target}",
                                plan=plan, approval_id=run.approval.approval_id,
                                execution_status=ExecutionStatus.PENDING_APPROVAL.value)
        run.incident = records.save_assessment(
            self._db, run.incident, assessment, IncidentStatus.REMEDIATION_PENDING, proposed, run.now,
            f"{run.method.value}:{plan.action.value}", assessment.confidence)  # type: ignore[union-attr]
        self._audit(proposed)
        self._audit(requested)
        return assessment

    # ----------------------------------------------------------------- results
    def _result(self, run: _Run, a: RemediationAssessment | None) -> AgentResult:
        incident_id = run.request.incident_id
        if a is None:
            return AgentResult(
                agent_name=self.name, incident_id=incident_id, status=run.status, outcome=run.outcome,
                confidence=0.0, reasoning_summary="No remediation plan was stored; the incident and the cloud are unchanged.",
                errors=run.errors or [run.outcome])
        plan = a.plan
        evidence = [Evidence(kind=e.type, event_id=e.raw_reference.get("event_id"), description=e.description,
                             collected_by=self.name, collected_at=run.now) for e in a.evidence]
        proposed = ([] if plan.action == RemediationAction.NO_ACTION else [ProposedAction(
            tool_name=plan.tool_name or plan.action.value, arguments=dict(plan.arguments), rationale=plan.reason)])
        return AgentResult(
            agent_name=self.name, incident_id=incident_id, status=AgentRunStatus.SUCCESS, outcome=run.outcome,
            confidence=a.confidence, reasoning_summary=plan.reason,
            findings=[f"method:{a.method.value}", f"action:{plan.action.value}", f"target:{plan.target or 'none'}",
                      f"risk:{plan.risk.value}", f"status:{a.status.value}"]
            + ([f"approval:{a.approval.approval_id}"] if a.approval else []) + [f"unknown:{u}" for u in a.unknowns],
            evidence=evidence,
            actions=[AgentAction(action="update_incident", target=incident_id,
                                 details={"fields": ["remediation", "final_status", "current_agent"]})]
            + ([AgentAction(action="request_approval", target=a.approval.approval_id)] if a.approval else []),
            proposed_actions=proposed, recommendations=a.recommendations, errors=run.errors, timestamp=run.now)

    def _entry(self, run: _Run, action: str, decision: str, result: str, **kwargs: Any) -> AuditEntry:
        return records.audit_entry(
            self._clock(), run.request.incident_id, action, decision, result, run_id=run.run_id,
            provider=self.provider_name, model=self.model_name,
            method=run.method.value if run.method else None, errors=run.errors, **kwargs)

    def _record(self, run: _Run, result: AgentResult) -> None:
        if result.status != AgentRunStatus.SUCCESS:
            self._audit(self._entry(run, "remediation.failed" if result.status == AgentRunStatus.FAILED
                                    else "remediation.blocked", result.status.value, run.outcome))
        records.record_run(self._db, run_id=run.run_id, started=run.now, finished=self._clock(),
                           incident_id=run.request.incident_id, result=result,
                           method=run.method.value if run.method else None,
                           provider=self.provider_name, model=self.model_name)
