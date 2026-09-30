"""The Compliance Agent (read-only).

    investigated incident -> gate -> deterministic analysis (assets, classification, candidate controls,
    configured framework mappings, matched rules, unknowns) -> bounded context -> LLM (text only)
    -> ComplianceDecision -> evidence / framework / control / semantic / policy validation
    (one repair attempt) -> backend finalization (statuses, derived mappings, overall + reporting
    status) -> incident.compliance update -> audit -> AgentResult

Earlier stages are never re-run or overwritten. Nothing is written unless a decision is valid.
This is a security-engineering aid, not legal advice.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.agents.base import BaseAgent
from app.agents.compliance.config import ComplianceSettings
from app.agents.compliance.context import ComplianceContext, ComplianceContextBuilder
from app.agents.compliance.fallback import rule_based_decision
from app.agents.compliance.prompts import SYSTEM_PROMPT, build_repair_prompt, build_user_prompt
from app.agents.compliance.validation import Finalized, debug_payload, finalize, validate_decision
from app.agents.structured import ask_structured
from app.database.connection import Database
from app.database.models import AgentRunRecord
from app.domain.agent_result import AgentAction, AgentResult
from app.domain.compliance import ComplianceAssessment, ComplianceDecision
from app.domain.enums import AgentName, AgentRunStatus, IncidentStatus, TriageMethod
from app.domain.events import utcnow
from app.domain.incident import AgentDecision, AuditEntry, Evidence, IncidentState
from app.llm.base import LLMProvider
from app.services.agent_runs import AgentRunService
from app.services.incident_service import IncidentService
from app.tools.executor import ToolExecutor

logger = logging.getLogger(__name__)

AuditSink = Callable[[AuditEntry], None]
_PROGRESSABLE = {IncidentStatus.INVESTIGATED, IncidentStatus.COMPLIANCE_ASSESSED}
DECISION_SCHEMA = ComplianceDecision.model_json_schema()


class ComplianceRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=36, pattern=r"^[A-Za-z0-9_-]+$")
    allow_rule_based_fallback: bool = Field(
        default=False, description="If no valid LLM decision is obtained, apply the deterministic "
                                   "rule_based_fallback (clearly labelled) instead of failing.")


class ComplianceRunReport(BaseModel):
    run_id: str
    incident_id: str
    status: AgentRunStatus
    outcome: str
    method: TriageMethod | None
    provider: str | None
    model: str | None
    attempts: int
    validation_errors: list[str]
    compliance: ComplianceAssessment | None
    agent_result: AgentResult


@dataclass
class _Run:
    run_id: str
    now: datetime
    request: ComplianceRunRequest
    incident: IncidentState | None = None
    context: ComplianceContext | None = None
    decision: ComplianceDecision | None = None
    finalized: Finalized | None = None
    method: TriageMethod | None = None
    attempts: int = 0
    errors: list[str] = field(default_factory=list)
    outcome: str = ""
    status: AgentRunStatus = AgentRunStatus.FAILED


class ComplianceAgent(BaseAgent[ComplianceRunRequest, ComplianceRunReport]):
    name = AgentName.COMPLIANCE

    def __init__(self, database: Database, settings: ComplianceSettings, provider: LLMProvider | None,
                 tools: ToolExecutor | None, audit_sink: AuditSink,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self._db = database
        self._settings = settings
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
    def run(self, request: ComplianceRunRequest) -> ComplianceRunReport:
        run = _Run(run_id=f"CMP-{uuid4().hex[:10].upper()}", now=self._clock(), request=request)
        self._audit(self._entry(run, "compliance.run", "started", "compliance assessment started"))
        assessment: ComplianceAssessment | None = None
        try:
            with self._db.session() as session:
                run.incident = IncidentService(session).get(request.incident_id)
            if run.incident is None:
                run.outcome = "incident_not_found"
                run.errors.append(f"incident {request.incident_id} not found")
            elif run.incident.investigation is None:
                run.status, run.outcome = AgentRunStatus.SKIPPED, "investigation_required"
                run.errors.append("the incident has not been investigated; run the Investigator Agent first")
            else:
                run.context = ComplianceContextBuilder(self._settings, self._tools).build(run.incident)
                self._decide(run)
                if run.decision is not None:
                    assessment = self._apply(run)
                    run.status = AgentRunStatus.SUCCESS
        except Exception as exc:  # report, never crash the caller
            logger.exception("compliance run %s failed", run.run_id)
            run.status, run.outcome, assessment = AgentRunStatus.FAILED, "internal_error", None
            run.errors.append(f"internal_error:{type(exc).__name__}")
        result = self._result(run, assessment)
        self._record(run, result)
        return ComplianceRunReport(
            run_id=run.run_id, incident_id=request.incident_id, status=result.status, outcome=run.outcome,
            method=run.method, provider=self.provider_name, model=self.model_name, attempts=run.attempts,
            validation_errors=run.errors, compliance=assessment, agent_result=result)

    # ------------------------------------------------------------------ stages
    def _decide(self, run: _Run) -> None:
        assert run.context is not None
        context, settings = run.context, self._settings
        context_json = context.to_json()
        result = ask_structured(
            self._provider, SYSTEM_PROMPT, build_user_prompt(context_json), DECISION_SCHEMA,
            validate=lambda text: validate_decision(text, context, settings),
            repair=lambda previous, problems: build_repair_prompt(context_json, previous, problems),
            max_repairs=settings.config.policy.max_repair_attempts)
        run.attempts, run.errors = result.attempts, run.errors + result.errors
        if result.value is not None:
            run.decision, run.method, run.outcome = result.value, TriageMethod.LLM, "compliance_assessed"
        elif run.request.allow_rule_based_fallback:
            decision = rule_based_decision(context, settings)
            run.decision = validate_decision(decision.model_dump_json(), context, settings)
            run.method, run.outcome = TriageMethod.RULE_BASED_FALLBACK, "compliance_assessed_rule_based_fallback"
        else:
            run.outcome = result.failure
        if run.decision is not None:
            run.finalized = finalize(run.decision, context, settings)

    def _apply(self, run: _Run) -> ComplianceAssessment:
        incident, d, f, ctx = run.incident, run.decision, run.finalized, run.context
        assert incident and d and f and ctx and run.method and incident.investigation
        analysis, llm = ctx.analysis, run.method == TriageMethod.LLM
        assessment = ComplianceAssessment(
            run_id=run.run_id, method=run.method, provider=self.provider_name if llm else "rule_based",
            model=self.model_name if llm else "compliance_mapping.yaml", timestamp=run.now,
            input_event_ids=analysis.event_ids, based_on_investigation_run=incident.investigation.run_id,
            confidence=d.confidence, overall_status=f.overall_status, overall_note=f.overall_note,
            summary=d.summary, affected_assets=analysis.assets, affected_data=analysis.data,
            controls=f.controls, framework_assessments=f.frameworks, control_gaps=f.gaps,
            potential_violations=f.violations, reporting_status=f.reporting_status,
            reporting_considerations=f.reporting, recommendations=f.recommendations, unknowns=d.unknowns,
            standing_unknowns=analysis.standing_unknowns, matched_violation_rules=analysis.violation_matches,
            matched_reporting_rules=analysis.reporting_matches, evidence=list(analysis.evidence.values()))
        entry = self._entry(run, "compliance.completed", "success", self._summary_line(assessment),
                            confidence=d.confidence, assessment=assessment)
        progress = incident.final_status in _PROGRESSABLE
        updated = incident.model_copy(update={
            "compliance": assessment,
            "final_status": IncidentStatus.COMPLIANCE_ASSESSED if progress else incident.final_status,
            "current_agent": AgentName.COMPLIANCE if progress else incident.current_agent,
            # monitor / triage / investigation are intentionally left untouched
            "agent_decisions": [x for x in incident.agent_decisions if x.actor != AgentName.COMPLIANCE]
            + [AgentDecision(actor=AgentName.COMPLIANCE, timestamp=run.now, confidence=d.confidence,
                             decision=f"{run.method.value}:{f.overall_status.value}", reasoning=d.summary)],
            "audit_log": incident.audit_log + [entry],
        })
        with self._db.session() as session:
            run.incident = IncidentService(session).save(updated)
        self._audit(entry)
        return assessment

    # ----------------------------------------------------------------- results
    @staticmethod
    def _summary_line(a: ComplianceAssessment) -> str:
        return (f"overall {a.overall_status.value}; {len(a.controls)} control(s), "
                f"{len({x.framework for x in a.framework_assessments})} framework(s); reporting "
                f"{a.reporting_status.value} ({a.method.value})")

    def _result(self, run: _Run, a: ComplianceAssessment | None) -> AgentResult:
        incident_id = run.request.incident_id
        if a is None:
            return AgentResult(
                agent_name=self.name, incident_id=incident_id, status=run.status, outcome=run.outcome,
                confidence=0.0, reasoning_summary="No compliance assessment was applied; the incident is unchanged.",
                errors=run.errors or [run.outcome])
        cited = list(dict.fromkeys(e for c in a.controls for e in c.evidence_ids))
        by_id = {e.evidence_id: e for e in a.evidence}
        evidence = [Evidence(kind=by_id[i].type, event_id=by_id[i].raw_reference.get("event_id"),
                             description=by_id[i].description, collected_by=self.name, collected_at=run.now)
                    for i in cited if i in by_id]
        return AgentResult(
            agent_name=self.name, incident_id=incident_id, status=AgentRunStatus.SUCCESS, outcome=run.outcome,
            confidence=a.confidence, reasoning_summary=a.summary,
            findings=[f"method:{a.method.value}", f"overall:{a.overall_status.value}"]
            + [f"control:{c.control_id}:{c.status.value}:{','.join(c.evidence_ids)}" for c in a.controls]
            + [f"gap:{g.control_id}" for g in a.control_gaps]
            + [f"potential_violation:{v.control_id}:{v.status.value}:{v.rule_id or 'no_rule'}" for v in a.potential_violations]
            + [f"reporting:{a.reporting_status.value}"] + [f"unknown:{u}" for u in a.unknowns],
            evidence=evidence,
            actions=[AgentAction(action="update_incident", target=incident_id,
                                 details={"fields": ["compliance", "final_status", "current_agent"]})],
            recommendations=[f"{r.type.value}" + (f":{r.control_id}" if r.control_id else "")
                             for r in a.recommendations],
            errors=run.errors, timestamp=run.now)

    def _entry(self, run: _Run, action: str, decision: str, result: str, *, confidence: float | None = None,
               assessment: ComplianceAssessment | None = None) -> AuditEntry:
        details: dict[str, Any] = {
            "run_id": run.run_id, "provider": self.provider_name, "model": self.model_name,
            "method": run.method.value if run.method else None,
            "input_event_ids": run.context.analysis.event_ids if run.context else [],
            "attempts": run.attempts,
        }
        if run.finalized is not None:
            details["decision"] = debug_payload(run.finalized)
        if assessment is not None:
            details["decision"]["confidence"] = assessment.confidence
        if run.errors:
            details["errors"] = [e[:300] for e in run.errors[:10]]
        return AuditEntry(timestamp=self._clock(), incident_id=run.request.incident_id, actor=self.name,
                          action=action, decision=decision, result=result,
                          reasoning=assessment.summary if assessment else "", confidence=confidence, details=details)

    def _record(self, run: _Run, result: AgentResult) -> None:
        if result.status != AgentRunStatus.SUCCESS:
            self._audit(self._entry(run, "compliance.failed", result.status.value, run.outcome))
        try:
            with self._db.session() as session:
                AgentRunService(session).record(AgentRunRecord(
                    run_id=run.run_id, agent=self.name.value, incident_id=run.request.incident_id,
                    started_at=run.now, finished_at=self._clock(), status=result.status.value,
                    outcome=run.outcome, method=run.method.value if run.method else None,
                    provider=self.provider_name, model=self.model_name, confidence=result.confidence,
                    result=result.model_dump(mode="json", exclude={"evidence"})))
        except Exception:
            logger.exception("could not record compliance run %s", run.run_id)
