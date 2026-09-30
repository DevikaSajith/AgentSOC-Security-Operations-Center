"""The Investigator Agent (read-only).

    incident -> triage gate -> deterministic evidence collection (read tools, as Investigator)
      -> timeline -> entities/relationships -> MITRE candidates -> bounded context
      -> LLM (text only) -> InvestigationDecision -> semantic / evidence / MITRE / policy
      checks (one repair attempt) -> MITRE status decided by the backend
      -> incident.investigation update -> audit -> AgentResult

Triage is never re-run or overwritten. Nothing is written unless a decision is valid.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.agents.base import BaseAgent
from app.agents.investigator import mitre
from app.agents.investigator.config import InvestigatorConfig
from app.agents.investigator.context import InvestigationContext, InvestigationContextBuilder
from app.agents.investigator.fallback import rule_based_decision
from app.agents.investigator.prompts import SYSTEM_PROMPT, build_repair_prompt, build_user_prompt
from app.agents.investigator.validation import classify, validate_decision
from app.agents.structured import ask_structured
from app.database.connection import Database
from app.database.models import AgentRunRecord
from app.domain.agent_result import AgentAction, AgentResult
from app.domain.enums import AgentName, AgentRunStatus, IncidentStatus, TriageMethod
from app.domain.events import utcnow
from app.domain.incident import AgentDecision, AuditEntry, Evidence, IncidentState, MitreTechnique
from app.domain.investigation import (
    InvestigationAssessment,
    InvestigationDecision,
    MitreStatus,
)
from app.llm.base import LLMProvider
from app.services.agent_runs import AgentRunService
from app.services.incident_service import IncidentService
from app.tools.executor import ToolExecutor

logger = logging.getLogger(__name__)

AuditSink = Callable[[AuditEntry], None]
_INVESTIGABLE = {IncidentStatus.NEW, IncidentStatus.TRIAGING, IncidentStatus.TRIAGED,
                 IncidentStatus.INVESTIGATING, IncidentStatus.INVESTIGATED,
                 IncidentStatus.COMPLIANCE_ASSESSED}  # a new investigation makes compliance stale
DECISION_SCHEMA = InvestigationDecision.model_json_schema()


class InvestigationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=36, pattern=r"^[A-Za-z0-9_-]+$")
    allow_rule_based_fallback: bool = Field(
        default=False, description="If no valid LLM decision is obtained, apply the deterministic "
                                   "rule_based_fallback (clearly labelled) instead of failing.")
    allow_untriaged: bool = Field(
        default=False, description="Explicit override of the triage gate. Triage is never run automatically.")


class InvestigationRunReport(BaseModel):
    run_id: str
    incident_id: str
    status: AgentRunStatus
    outcome: str
    method: TriageMethod | None
    provider: str | None
    model: str | None
    attempts: int
    validation_errors: list[str]
    investigation: InvestigationAssessment | None
    agent_result: AgentResult


@dataclass
class _Run:
    run_id: str
    now: datetime
    request: InvestigationRunRequest
    incident: IncidentState | None = None
    context: InvestigationContext | None = None
    decision: InvestigationDecision | None = None
    method: TriageMethod | None = None
    attempts: int = 0
    errors: list[str] = field(default_factory=list)
    outcome: str = ""
    status: AgentRunStatus = AgentRunStatus.FAILED


class InvestigatorAgent(BaseAgent[InvestigationRunRequest, InvestigationRunReport]):
    name = AgentName.INVESTIGATOR

    def __init__(self, database: Database, config: InvestigatorConfig, provider: LLMProvider | None,
                 tools: ToolExecutor | None, audit_sink: AuditSink, config_dir: Path,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self._db = database
        self._config = config
        self._provider = provider
        self._tools = tools
        self._audit = audit_sink
        self._config_dir = config_dir
        self._clock = clock

    @property
    def provider_name(self) -> str | None:
        return self._provider.name if self._provider else None

    @property
    def model_name(self) -> str | None:
        return self._provider.model if self._provider else None

    # --------------------------------------------------------------------- run
    def run(self, request: InvestigationRunRequest) -> InvestigationRunReport:
        run = _Run(run_id=f"INV-{uuid4().hex[:10].upper()}", now=self._clock(), request=request)
        self._audit(self._entry(run, "investigator.run", "started", "investigation started"))
        assessment: InvestigationAssessment | None = None
        try:
            with self._db.session() as session:
                run.incident = IncidentService(session).get(request.incident_id)
            if run.incident is None:
                run.outcome = "incident_not_found"
                run.errors.append(f"incident {request.incident_id} not found")
            elif run.incident.triage is None and not request.allow_untriaged:
                run.status, run.outcome = AgentRunStatus.SKIPPED, "triage_required"
                run.errors.append("the incident has not been triaged; run the Triage Agent first")
            elif not any(e.kind == "event" for e in run.incident.evidence):
                run.status, run.outcome = AgentRunStatus.SKIPPED, "insufficient_context"
                run.errors.append("the incident has no event evidence to investigate")
            else:
                run.context = InvestigationContextBuilder(self._config, self._tools,
                                                          self._config_dir).build(run.incident)
                if not run.context.catalog.events:
                    run.status, run.outcome = AgentRunStatus.SKIPPED, "insufficient_context"
                    run.errors.append("no incident events could be collected")
                else:
                    self._decide(run)
                    if run.decision is not None:
                        assessment = self._apply(run)
                        run.status = AgentRunStatus.SUCCESS
        except Exception as exc:  # report, never crash the caller
            logger.exception("investigation run %s failed", run.run_id)
            run.status, run.outcome, assessment = AgentRunStatus.FAILED, "internal_error", None
            run.errors.append(f"internal_error:{type(exc).__name__}")
        result = self._result(run, assessment)
        self._record(run, result)
        return InvestigationRunReport(
            run_id=run.run_id, incident_id=request.incident_id, status=result.status, outcome=run.outcome,
            method=run.method, provider=self.provider_name, model=self.model_name, attempts=run.attempts,
            validation_errors=run.errors, investigation=assessment, agent_result=result)

    # ------------------------------------------------------------------ stages
    def _validate(self, text: str, run: _Run) -> InvestigationDecision:
        assert run.context is not None
        return validate_decision(text, run.context, self._config, self._config_dir)

    def _decide(self, run: _Run) -> None:
        assert run.context is not None
        context_json = run.context.to_json()
        result = ask_structured(
            self._provider, SYSTEM_PROMPT, build_user_prompt(context_json), DECISION_SCHEMA,
            validate=lambda text: self._validate(text, run),
            repair=lambda previous, problems: build_repair_prompt(context_json, previous, problems),
            max_repairs=self._config.policy.max_repair_attempts)
        run.attempts, run.errors = result.attempts, run.errors + result.errors
        if result.value is not None:
            run.decision, run.method, run.outcome = result.value, TriageMethod.LLM, "investigated"
        elif run.request.allow_rule_based_fallback:
            decision = rule_based_decision(run.context, self._config)
            run.decision = self._validate(decision.model_dump_json(), run)
            run.method, run.outcome = TriageMethod.RULE_BASED_FALLBACK, "investigated_rule_based_fallback"
        else:
            run.outcome = result.failure

    def _apply(self, run: _Run) -> InvestigationAssessment:
        incident, d, ctx = run.incident, run.decision, run.context
        assert incident is not None and d is not None and ctx is not None and run.method is not None
        notes = {n.evidence_id: n.significance for n in d.timeline_notes}
        timeline = [t.model_copy(update={"significance": notes.get(t.evidence_id)}) for t in ctx.timeline]
        techniques = mitre.assess(d.mitre_techniques, ctx.catalog, self._config_dir, self._config)
        findings, stages = classify(d, ctx, self._config)  # backend decides final certainty
        llm = run.method == TriageMethod.LLM
        assessment = InvestigationAssessment(
            run_id=run.run_id, method=run.method,
            provider=self.provider_name if llm else "rule_based",
            model=self.model_name if llm else "investigator_rules.yaml",
            timestamp=run.now, input_event_ids=ctx.catalog.event_ids,
            based_on_triage_run=incident.triage.run_id if incident.triage else None,
            confidence=d.confidence, summary=d.summary, evidence=list(ctx.catalog.items.values()),
            timeline=timeline, entities=ctx.entities, relationships=ctx.relationships,
            attack_sequence=stages, findings=findings,
            mitre_techniques=techniques, root_cause_hypothesis=d.root_cause_hypothesis,
            unknowns=d.unknowns, limitations=ctx.catalog.limitations,
            alternative_hypotheses=d.alternative_hypotheses, recommended_next_step=d.recommended_next_step)
        event_ids = {e.evidence_id: e.event_id for e in ctx.catalog.events}
        confirmed = [MitreTechnique(technique_id=t.technique_id, name=t.technique_name, tactic=t.tactic,
                                    confidence=t.confidence,
                                    evidence_ids=[event_ids[i] for i in t.evidence_ids if i in event_ids])
                     for t in techniques if t.status == MitreStatus.CONFIRMED]
        entry = self._entry(run, "investigator.completed", "success", self._summary_line(assessment),
                            confidence=d.confidence, assessment=assessment)
        progress = incident.final_status in _INVESTIGABLE
        updated = incident.model_copy(update={
            "investigation": assessment,
            "mitre_techniques": confirmed,  # only backend-confirmed techniques
            "final_status": IncidentStatus.INVESTIGATED if progress else incident.final_status,
            "current_agent": AgentName.INVESTIGATOR if progress else incident.current_agent,
            # triage (and severity/priority/category) is intentionally left untouched
            "agent_decisions": [x for x in incident.agent_decisions if x.actor != AgentName.INVESTIGATOR]
            + [AgentDecision(actor=AgentName.INVESTIGATOR, timestamp=run.now, confidence=d.confidence,
                             decision=f"{run.method.value}:{d.recommended_next_step.value}",
                             reasoning=d.summary)],
            "audit_log": incident.audit_log + [entry],
        })
        with self._db.session() as session:
            run.incident = IncidentService(session).save(updated)
        self._audit(entry)
        return assessment

    # ----------------------------------------------------------------- results
    @staticmethod
    def _summary_line(a: InvestigationAssessment) -> str:
        confirmed = [t.technique_id for t in a.mitre_techniques if t.status == MitreStatus.CONFIRMED]
        return (f"{len(a.findings)} finding(s), {len(a.attack_sequence)} stage(s), MITRE confirmed: "
                f"{', '.join(confirmed) or 'none'} -> {a.recommended_next_step.value} ({a.method.value})")

    def _result(self, run: _Run, a: InvestigationAssessment | None) -> AgentResult:
        incident_id = run.request.incident_id
        if a is None:
            return AgentResult(
                agent_name=self.name, incident_id=incident_id, status=run.status, outcome=run.outcome,
                confidence=0.0, reasoning_summary="No investigation was applied; the incident is unchanged.",
                errors=run.errors or [run.outcome])
        existing = {e.evidence_id: e for e in (run.incident.evidence if run.incident else [])}
        evidence = []
        for item in a.evidence:
            if item.type in ("event", "network"):
                monitor_id = item.raw_reference.get("monitor_evidence_id")
                evidence.append(existing.get(monitor_id) or Evidence(
                    kind="event", event_id=item.raw_reference.get("event_id"), description=item.description,
                    collected_by=self.name, collected_at=run.now))
        return AgentResult(
            agent_name=self.name, incident_id=incident_id, status=AgentRunStatus.SUCCESS,
            outcome=run.outcome, confidence=a.confidence, reasoning_summary=a.summary,
            findings=[f"method:{a.method.value}"]
            + [f"finding:{f.finding_id}:{f.type.value}:{f.classification.value}:{','.join(f.evidence_ids)}"
               for f in a.findings]
            + [f"stage:{s.order}:{s.stage.value}:{s.certainty.value}" for s in a.attack_sequence]
            + [f"mitre:{t.technique_id}:{t.status.value}" for t in a.mitre_techniques]
            + [f"hypothesis:{a.root_cause_hypothesis}"]
            + [f"unknown:{u}" for u in a.unknowns],
            evidence=evidence,
            actions=[AgentAction(action="update_incident", target=incident_id,
                                 details={"fields": ["investigation", "mitre_techniques", "final_status",
                                                     "current_agent"]})],
            recommendations=[f"next_step:{a.recommended_next_step.value}:{incident_id}"],
            errors=run.errors, timestamp=run.now)

    def _entry(self, run: _Run, action: str, decision: str, result: str, *,
               confidence: float | None = None,
               assessment: InvestigationAssessment | None = None) -> AuditEntry:
        details: dict[str, Any] = {
            "run_id": run.run_id, "provider": self.provider_name, "model": self.model_name,
            "method": run.method.value if run.method else None,
            "input_event_ids": run.context.catalog.event_ids if run.context else [],
            "attempts": run.attempts,
        }
        if assessment is not None:
            details["decision"] = {
                "confidence": assessment.confidence,
                "findings": [f"{f.finding_id}:{f.type.value}:{f.classification.value}" for f in assessment.findings],
                "mitre": [f"{t.technique_id}:{t.status.value}" for t in assessment.mitre_techniques],
                "recommended_next_step": assessment.recommended_next_step.value}
        if run.errors:
            details["errors"] = [e[:300] for e in run.errors[:10]]
        return AuditEntry(timestamp=self._clock(), incident_id=run.request.incident_id, actor=self.name,
                          action=action, decision=decision, result=result,
                          reasoning=assessment.summary if assessment else "", confidence=confidence,
                          details=details)

    def _record(self, run: _Run, result: AgentResult) -> None:
        if result.status != AgentRunStatus.SUCCESS:
            self._audit(self._entry(run, "investigator.failed", result.status.value, run.outcome))
        try:
            with self._db.session() as session:
                AgentRunService(session).record(AgentRunRecord(
                    run_id=run.run_id, agent=self.name.value, incident_id=run.request.incident_id,
                    started_at=run.now, finished_at=self._clock(), status=result.status.value,
                    outcome=run.outcome, method=run.method.value if run.method else None,
                    provider=self.provider_name, model=self.model_name, confidence=result.confidence,
                    result=result.model_dump(mode="json", exclude={"evidence"})))
        except Exception:
            logger.exception("could not record investigation run %s", run.run_id)
