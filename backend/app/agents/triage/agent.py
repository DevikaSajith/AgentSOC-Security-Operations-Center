"""The Triage Agent: the first reasoning agent.

    IncidentState -> evidence collection (read tools, as Triage) -> bounded context
      -> LLM (text only) -> JSON -> Pydantic TriageDecision -> semantic + policy checks
      -> (one constrained repair attempt if rejected) -> IncidentState update -> audit
      -> AgentResult

The model never touches the system: it receives a JSON context and returns text. Only a
validated decision updates the incident. If no valid decision is obtained the incident is
left untouched and the run is reported as failed - unless the caller explicitly allowed
the rule_based_fallback, which is always labelled as such.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.agents.base import BaseAgent
from app.agents.triage.config import TriageConfig
from app.agents.triage.context import ContextBuilder, TriageContext
from app.agents.triage.fallback import rule_based_decision
from app.agents.triage.prompts import SYSTEM_PROMPT, build_repair_prompt, build_user_prompt
from app.agents.structured import ask_structured
from app.agents.triage.validation import validate_decision
from app.database.connection import Database
from app.database.models import AgentRunRecord
from app.domain.agent_result import AgentAction, AgentResult
from app.domain.enums import AgentName, AgentRunStatus, IncidentStatus, TriageMethod
from app.domain.events import utcnow
from app.domain.incident import AgentDecision, AuditEntry, Evidence, IncidentState
from app.domain.triage import PriorAssessment, TriageAssessment, TriageDecision, TriageInterpretation
from app.llm.base import LLMProvider
from app.services.agent_runs import AgentRunService
from app.services.incident_service import IncidentService
from app.tools.executor import ToolExecutor

logger = logging.getLogger(__name__)

AuditSink = Callable[[AuditEntry], None]
# Triage may move an incident to TRIAGED only from these statuses (never backwards).
_TRIAGEABLE = {IncidentStatus.NEW, IncidentStatus.TRIAGING, IncidentStatus.TRIAGED}
DECISION_SCHEMA = TriageDecision.model_json_schema()


class TriageRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=36, pattern=r"^[A-Za-z0-9_-]+$")
    allow_rule_based_fallback: bool = Field(
        default=False, description="If no valid LLM decision is obtained, apply the deterministic "
                                   "rule_based_fallback instead of failing (clearly labelled).")


class TriageRunReport(BaseModel):
    run_id: str
    incident_id: str
    status: AgentRunStatus
    outcome: str
    method: TriageMethod | None
    provider: str | None
    model: str | None
    attempts: int
    validation_errors: list[str]
    triage: TriageAssessment | None
    agent_result: AgentResult


@dataclass
class _Run:
    run_id: str
    now: datetime
    request: TriageRunRequest
    incident: IncidentState | None = None
    context: TriageContext | None = None
    decision: TriageDecision | None = None
    method: TriageMethod | None = None
    attempts: int = 0
    errors: list[str] = field(default_factory=list)
    outcome: str = ""


class TriageAgent(BaseAgent[TriageRunRequest, TriageRunReport]):
    name = AgentName.TRIAGE

    def __init__(self, database: Database, config: TriageConfig, provider: LLMProvider | None,
                 tools: ToolExecutor | None, audit_sink: AuditSink,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self._db = database
        self._config = config
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
    def run(self, request: TriageRunRequest) -> TriageRunReport:
        run = _Run(run_id=f"TRI-{uuid4().hex[:10].upper()}", now=self._clock(), request=request)
        self._audit_event(run, "triage.run", "started", "triage started")
        triage: TriageAssessment | None = None
        try:
            run.incident = self._load(request.incident_id)
            if run.incident is None:
                run.outcome = "incident_not_found"
                run.errors.append(f"incident {request.incident_id} not found")
            else:
                run.context = ContextBuilder(self._config, self._tools).build(run.incident)
                self._decide(run)
                if run.decision is not None:
                    triage = self._apply(run)
        except Exception as exc:  # report, never crash the caller
            logger.exception("triage run %s failed", run.run_id)
            run.outcome, triage = "internal_error", None
            run.errors.append(f"internal_error:{type(exc).__name__}")
        result = self._result(run, triage)
        self._record(run, result)
        return TriageRunReport(
            run_id=run.run_id, incident_id=request.incident_id, status=result.status,
            outcome=run.outcome, method=run.method, provider=self.provider_name,
            model=self.model_name, attempts=run.attempts, validation_errors=run.errors,
            triage=triage, agent_result=result)

    # ------------------------------------------------------------------ stages
    def _load(self, incident_id: str) -> IncidentState | None:
        with self._db.session() as session:
            return IncidentService(session).get(incident_id)

    def _decide(self, run: _Run) -> None:
        assert run.context is not None and run.incident is not None
        llm_failure = self._ask_llm(run)
        if run.decision is not None:
            run.method, run.outcome = TriageMethod.LLM, "triaged"
            return
        if run.request.allow_rule_based_fallback:
            run.decision = rule_based_decision(run.incident, run.context, self._config)
            validate_decision(run.decision.model_dump_json(), set(run.context.facts), self._config,
                              run.context.ml_probability)
            run.method, run.outcome = TriageMethod.RULE_BASED_FALLBACK, "triaged_rule_based_fallback"
            return
        run.outcome = llm_failure

    def _ask_llm(self, run: _Run) -> str:
        """Fills run.decision on success; otherwise returns the failure outcome."""
        assert run.context is not None
        context_json = run.context.to_json()
        allowed = set(run.context.facts)
        ml_probability = run.context.ml_probability
        result = ask_structured(
            self._provider, SYSTEM_PROMPT, build_user_prompt(context_json), DECISION_SCHEMA,
            validate=lambda text: validate_decision(text, allowed, self._config, ml_probability),
            repair=lambda previous, problems: build_repair_prompt(context_json, previous, problems),
            max_repairs=self._config.policy.max_repair_attempts)
        run.attempts += result.attempts
        run.errors.extend(result.errors)
        run.decision = result.value
        return result.failure or "triaged"

    def _apply(self, run: _Run) -> TriageAssessment:
        """Update the incident from the validated decision (latest triage replaces older)."""
        incident, decision, context = run.incident, run.decision, run.context
        assert incident is not None and decision is not None and context is not None and run.method
        previous = incident.triage.previous if incident.triage else PriorAssessment(
            severity=incident.severity, priority=incident.priority, category=incident.category,
            confidence=incident.confidence)
        observed = [context.facts[ref] for ref in dict.fromkeys(decision.key_evidence)]
        assessment = TriageAssessment(
            run_id=run.run_id, method=run.method,
            provider=self.provider_name if run.method == TriageMethod.LLM else "rule_based",
            model=self.model_name if run.method == TriageMethod.LLM else "triage_rules.yaml",
            timestamp=run.now, input_event_ids=context.input_event_ids,
            severity=decision.severity, priority=decision.priority, category=decision.category,
            confidence=decision.confidence, previous=previous, observed_evidence=observed,
            interpretation=TriageInterpretation(
                classification=decision.classification, summary=decision.summary,
                severity_rationale=decision.severity_rationale,
                priority_rationale=decision.priority_rationale,
                risk_indicators=decision.risk_indicators,
                investigation_reason=decision.investigation_reason),
            investigation_required=decision.investigation_required,
            recommended_next_step=decision.recommended_next_step)
        entry = self._entry(run, "triage.completed", "success", self._summary_line(decision, run.method),
                            incident_id=incident.incident_id, confidence=decision.confidence)
        triaged = incident.final_status in _TRIAGEABLE
        updated = incident.model_copy(update={
            "severity": decision.severity, "priority": decision.priority,
            "category": decision.category, "confidence": decision.confidence,
            "triage": assessment,
            "final_status": IncidentStatus.TRIAGED if triaged else incident.final_status,
            "current_agent": AgentName.TRIAGE if triaged else incident.current_agent,
            # only the latest triage decision is kept; every run stays in the audit trail
            "agent_decisions": [d for d in incident.agent_decisions if d.actor != AgentName.TRIAGE]
            + [AgentDecision(actor=AgentName.TRIAGE, timestamp=run.now,
                             decision=f"{run.method.value}:{decision.recommended_next_step.value}",
                             reasoning=decision.summary, confidence=decision.confidence)],
            "audit_log": incident.audit_log + [entry],
        })
        with self._db.session() as session:
            run.incident = IncidentService(session).save(updated)
        self._audit(entry)
        return assessment

    # ----------------------------------------------------------------- results
    @staticmethod
    def _summary_line(decision: TriageDecision, method: TriageMethod) -> str:
        return (f"{decision.severity.value}/{decision.priority.value}/{decision.category.value} "
                f"-> {decision.recommended_next_step.value} ({method.value})")

    def _result(self, run: _Run, triage: TriageAssessment | None) -> AgentResult:
        incident_id = run.request.incident_id
        if triage is None:
            return AgentResult(
                agent_name=self.name, incident_id=incident_id, status=AgentRunStatus.FAILED,
                outcome=run.outcome, confidence=0.0,
                reasoning_summary="No triage decision was applied; the incident is unchanged.",
                errors=run.errors or [run.outcome])
        prev = triage.previous
        existing = {e.evidence_id: e for e in (run.incident.evidence if run.incident else [])}
        evidence = [existing.get(f.evidence_id) or Evidence(
            kind=f.kind, description=f.fact, event_id=f.event_id, collected_by=self.name,
            collected_at=run.now) for f in triage.observed_evidence]
        return AgentResult(
            agent_name=self.name, incident_id=incident_id, status=AgentRunStatus.SUCCESS,
            outcome=run.outcome, confidence=triage.confidence,
            reasoning_summary=triage.interpretation.summary,
            findings=[f"method:{triage.method.value}",
                      f"severity:{prev.severity.value}->{triage.severity.value}",
                      f"priority:{prev.priority.value if prev.priority else 'none'}->{triage.priority.value}",
                      f"category:{prev.category.value}->{triage.category.value}",
                      f"classification:{triage.interpretation.classification}",
                      f"investigation_required:{str(triage.investigation_required).lower()}",
                      f"next_step:{triage.recommended_next_step.value}"]
            + [f"interpretation:risk_indicator:{i.indicator}" for i in triage.interpretation.risk_indicators],
            evidence=evidence,
            actions=[AgentAction(action="update_incident", target=incident_id,
                                 details={"fields": ["severity", "priority", "category", "confidence",
                                                     "triage", "final_status"]})],
            recommendations=[f"next_step:{triage.recommended_next_step.value}:{incident_id}"],
            errors=run.errors,  # e.g. a rejected first answer that was repaired
            timestamp=run.now)

    # ---------------------------------------------------------- audit + history
    def _entry(self, run: _Run, action: str, decision: str, result: str, *,
               incident_id: str | None = None, confidence: float | None = None) -> AuditEntry:
        details: dict[str, Any] = {
            "run_id": run.run_id, "provider": self.provider_name, "model": self.model_name,
            "method": run.method.value if run.method else None,
            "input_event_ids": run.context.input_event_ids if run.context else [],
            "attempts": run.attempts,
        }
        if run.decision is not None:
            d = run.decision
            details["decision"] = {"severity": d.severity.value, "priority": d.priority.value,
                                   "category": d.category.value, "confidence": d.confidence,
                                   "classification": d.classification,
                                   "investigation_required": d.investigation_required,
                                   "recommended_next_step": d.recommended_next_step.value}
        if run.errors:
            details["errors"] = [e[:300] for e in run.errors[:10]]
        return AuditEntry(timestamp=self._clock(), incident_id=incident_id or run.request.incident_id,
                          actor=self.name, action=action, decision=decision, result=result,
                          reasoning=run.decision.summary if run.decision else "",
                          confidence=confidence, details=details)

    def _audit_event(self, run: _Run, action: str, decision: str, result: str) -> None:
        self._audit(self._entry(run, action, decision, result))

    def _record(self, run: _Run, result: AgentResult) -> None:
        if result.status == AgentRunStatus.FAILED:
            self._audit_event(run, "triage.failed", "failed", run.outcome)
        try:
            with self._db.session() as session:
                AgentRunService(session).record(AgentRunRecord(
                    run_id=run.run_id, agent=self.name.value, incident_id=run.request.incident_id,
                    started_at=run.now, finished_at=self._clock(), status=result.status.value,
                    outcome=run.outcome, method=run.method.value if run.method else None,
                    provider=self.provider_name, model=self.model_name,
                    confidence=result.confidence,
                    result=result.model_dump(mode="json", exclude={"evidence"})))
        except Exception:
            logger.exception("could not record triage run %s", run.run_id)
