"""The Feedback & Learning Engine: a deterministic backend service (NOT an LLM agent).

    verification result -> outcome classification -> failure analysis -> recommendation -> learning record
    (+ human feedback, controlled retry requests, regression detection)

It consumes structured incident data only (never prompts, raw model output or reasoning) and it can only
RECOMMEND. It has no action-tool permission and no way to execute or approve anything: a retry request only
records the request; the caller may then start the EXISTING remediation planning workflow, whose result is a
proposal that still needs human approval, the kill switch and the ToolExecutor. Regression detection re-reads
the target through the read-only tool `get_resource` and never remediates.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.agents.feedback.classify import analyze_failure, feedback_type_for, recommend
from app.agents.feedback.config import FeedbackRules
from app.agents.remediation.state import parse_target, read_state
from app.agents.verification.comparison import compare
from app.agents.verification.config import VerificationRules
from app.database.connection import Database
from app.database.models import AgentRunRecord
from app.domain.enums import AgentName, AgentRunStatus, HumanActor
from app.domain.events import utcnow
from app.domain.incident import AuditEntry, IncidentState
from app.domain.learning import (
    HUMAN_TO_FEEDBACK,
    FailureReason,
    FeedbackType,
    HumanFeedback,
    LearningRecord,
    Recommendation,
)
from app.domain.verification import VerificationStatus
from app.services.agent_runs import AgentRunService
from app.services.incident_service import IncidentService
from app.services.learning import LearningService
from app.tools.executor import ToolExecutor

logger = logging.getLogger(__name__)
AuditSink = Callable[[AuditEntry], None]
SERVICE_LABEL = "Feedback & Learning Service"
OUTCOME_TYPES = {FeedbackType.SUCCESSFUL_RESPONSE, FeedbackType.FAILED_RESPONSE, FeedbackType.PARTIAL_RESPONSE,
                 FeedbackType.INSUFFICIENT_EVIDENCE}


class LearningNotFoundError(LookupError):
    pass


class FeedbackRequestError(RuntimeError):
    """A controlled refusal: `code` is machine-readable (retry_not_applicable, retry_limit_reached, ...)."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class FeedbackRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=36, pattern=r"^[A-Za-z0-9_-]+$")


class HumanFeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    learning_id: str | None = Field(default=None, min_length=1, max_length=40)
    incident_id: str | None = Field(default=None, min_length=1, max_length=36, pattern=r"^[A-Za-z0-9_-]+$")
    feedback: HumanFeedback
    comment: str | None = Field(default=None, max_length=500)


class RetryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=500)
    allow_rule_based_fallback: bool = False


class FeedbackRunReport(BaseModel):
    run_id: str
    incident_id: str
    status: AgentRunStatus
    outcome: str
    learning: list[LearningRecord]
    regression_detected: bool
    validation_errors: list[str]


@dataclass
class _Run:
    run_id: str
    now: datetime
    incident_id: str
    records: list[LearningRecord] = field(default_factory=list)
    regression: bool = False
    status: AgentRunStatus = AgentRunStatus.FAILED
    outcome: str = ""
    errors: list[str] = field(default_factory=list)


class FeedbackEngine:
    def __init__(self, database: Database, rules: FeedbackRules, verification_rules: VerificationRules,
                 tools: ToolExecutor | None, audit_sink: AuditSink, clock: Callable[[], datetime] = utcnow) -> None:
        self._db = database
        self._rules = rules
        self._vrules = verification_rules
        self._tools = tools
        self._audit = audit_sink
        self._clock = clock

    @property
    def retry_limit(self) -> int:
        return self._rules.retry_limit

    # ------------------------------------------------------------------ run
    def run(self, request: FeedbackRunRequest) -> FeedbackRunReport:
        run = _Run(run_id=f"FBK-{uuid4().hex[:10].upper()}", now=self._clock(), incident_id=request.incident_id)
        try:
            with self._db.session() as session:
                incident = IncidentService(session).get(request.incident_id)
            if incident is None:
                run.outcome = "incident_not_found"
                run.errors.append(f"incident {request.incident_id} not found")
            elif incident.verification is None or incident.remediation is None:
                run.status, run.outcome = AgentRunStatus.SKIPPED, "verification_required"
                run.errors.append("the incident has no verification result yet; run the Verification Agent first")
            else:
                self._learn(run, incident)
                run.status = AgentRunStatus.SUCCESS
        except Exception as exc:  # report, never crash the caller
            logger.exception("feedback run %s failed", run.run_id)
            run.status, run.outcome = AgentRunStatus.FAILED, "internal_error"
            run.errors.append(f"internal_error:{type(exc).__name__}")
        self._record_run(run)
        return FeedbackRunReport(run_id=run.run_id, incident_id=run.incident_id, status=run.status, outcome=run.outcome,
                                 learning=run.records, regression_detected=run.regression, validation_errors=run.errors)

    def _learn(self, run: _Run, incident: IncidentState) -> None:
        v = incident.verification
        assert v is not None
        with self._db.session() as session:
            service = LearningService(session)
            existing = next((r for r in service.for_incident(incident.incident_id)
                             if r.verification_run_id == v.run_id and r.auto_feedback_type in OUTCOME_TYPES), None)
            retries = service.retry_count(incident.incident_id)
            if existing is not None:
                record, created = existing, False
            else:
                feedback = feedback_type_for(v.status, self._rules)
                reason = analyze_failure(incident, v, self._vrules)
                record = self._build(incident, feedback, reason, recommend(feedback, reason, retries, self._rules), run.now)
                record, created = service.save(record), True
        run.records.append(record)
        run.outcome = f"learning_{'created' if created else 'exists'}"
        if created:
            self._audit(self._entry(run.now, incident.incident_id, "learning.created", record.feedback_type.value,
                                    f"{record.feedback_type.value}: {record.remediation_action} on {record.remediation_target}",
                                    record))
            if record.failure_reason is not None:
                self._audit(self._entry(run.now, incident.incident_id, "learning.failure_analyzed",
                                        record.failure_reason.value,
                                        f"failure classified as {record.failure_reason.value}; recommendation "
                                        f"{record.recommendation.value}", record))
        regression = self.check_regression(incident, run.now)
        if regression is not None:
            run.regression = True
            run.records.append(regression)
            run.outcome += "_regression_detected"

    # ----------------------------------------------------------- regression
    def check_regression(self, incident: IncidentState, now: datetime | None = None) -> LearningRecord | None:
        """A previously VERIFIED remediation whose expected state no longer holds. Records it; never remediates."""
        now = now or self._clock()
        v = incident.verification
        if v is None or v.status != VerificationStatus.VERIFIED or not v.expected_state:
            return None
        parts = parse_target(v.target)
        if parts is None:
            return None
        raw = read_state(self._tools, incident.incident_id, parts[0], parts[1], actor=AgentName.VERIFICATION)
        if raw is None:
            return None  # cannot tell: no claim is made
        rows = compare(v.before_state, v.expected_state, raw)
        if all(r.satisfied for r in rows):
            return None
        with self._db.session() as session:
            service = LearningService(session)
            known = service.find(v.run_id, FeedbackType.REGRESSION_DETECTED)
            if known is not None:
                return known
            retries = service.retry_count(incident.incident_id)
            record = self._build(incident, FeedbackType.REGRESSION_DETECTED, FailureReason.STATE_REGRESSION,
                                 recommend(FeedbackType.REGRESSION_DETECTED, FailureReason.STATE_REGRESSION, retries, self._rules),
                                 now, result_override={
                                     "expected_state": v.expected_state, "actual_state": {r.field: r.actual for r in rows},
                                     "failure_reason": "state_regression", "verified_at": v.timestamp.isoformat()})
            record = service.save(record)
        self._audit(self._entry(now, incident.incident_id, "learning.regression_detected", "regression_detected",
                                "; ".join(f"{r.field}: expected {r.expected}, now {r.actual}" for r in rows if not r.satisfied),
                                record))
        return record

    # ------------------------------------------------------------ human feedback
    def submit_human_feedback(self, request: HumanFeedbackRequest) -> LearningRecord:
        if (request.learning_id is None) == (request.incident_id is None):
            raise FeedbackRequestError("give exactly one of learning_id or incident_id", "invalid_request")
        with self._db.session() as session:
            service = LearningService(session)
            if request.learning_id:
                record = service.get(request.learning_id)
            else:
                record = next((r for r in service.for_incident(request.incident_id or "")
                               if r.auto_feedback_type in OUTCOME_TYPES), None)
            if record is None:
                raise LearningNotFoundError("no learning record found; run the feedback service for the incident first")
            if record.auto_feedback_type == FeedbackType.RETRY_REQUESTED:
                raise FeedbackRequestError("feedback applies to outcome records, not retry requests", "invalid_request")
            effective = HUMAN_TO_FEEDBACK[request.feedback]
            updated = record.model_copy(update={
                "human_feedback": request.feedback, "human_comment": request.comment, "feedback_type": effective,
                "successful": effective == FeedbackType.SUCCESSFUL_RESPONSE})
            updated = service.save(updated)
        self._audit(AuditEntry(
            timestamp=self._clock(), incident_id=updated.incident_id, actor=HumanActor.ANALYST,
            action="learning.feedback_submitted", decision=request.feedback.value,
            result=f"analyst marked the response {request.feedback.value}"
            + (" (overrides the inferred feedback)" if updated.feedback_type != updated.auto_feedback_type else ""),
            details={"learning_id": updated.learning_id, "inferred": updated.auto_feedback_type.value,
                     "effective": updated.feedback_type.value, "has_comment": bool(request.comment)}))
        return updated

    # ------------------------------------------------------------------ retry
    def request_retry(self, incident_id: str, reason: str | None) -> LearningRecord:
        """Record a human's retry request (count, limit, previous run, reason) + audit. It executes NOTHING."""
        with self._db.session() as session:
            incident = IncidentService(session).get(incident_id)
        if incident is None:
            raise LearningNotFoundError(f"incident '{incident_id}' not found")
        v, r = incident.verification, incident.remediation
        with self._db.session() as session:
            service = LearningService(session)
            regressed = any(x.feedback_type == FeedbackType.REGRESSION_DETECTED and v and x.verification_run_id == v.run_id
                            for x in service.for_incident(incident_id))
            if v is None or r is None:
                raise FeedbackRequestError("there is no verified remediation to retry", "retry_not_applicable")
            if v.status == VerificationStatus.VERIFIED and not regressed:
                raise FeedbackRequestError("the remediation is verified; a retry is not needed", "retry_not_applicable")
            used = service.retry_count(incident_id)
            if used >= self._rules.retry_limit:
                raise FeedbackRequestError(f"the retry limit ({self._rules.retry_limit}) is reached; a human must decide "
                                           "how to proceed", "retry_limit_reached")
            outcome = next((x for x in service.for_incident(incident_id) if x.auto_feedback_type in OUTCOME_TYPES), None)
            record = self._build(incident, FeedbackType.RETRY_REQUESTED, outcome.failure_reason if outcome else None,
                                 Recommendation.RETRY_SAME_ACTION, self._clock(),
                                 retry=(used + 1, r.run_id, (reason or "analyst requested a retry")[:500]))
            record = service.save(record)
        self._audit(AuditEntry(
            timestamp=self._clock(), incident_id=incident_id, actor=HumanActor.ANALYST, action="learning.retry_requested",
            decision="retry_requested", result=f"retry {record.retry_count}/{record.retry_limit} requested (no action executed)",
            details={"learning_id": record.learning_id, "retry_count": record.retry_count, "retry_limit": record.retry_limit,
                     "previous_run_id": record.previous_run_id, "retry_reason": record.retry_reason,
                     "action": record.remediation_action, "target": record.remediation_target}))
        return record

    def attach_retry_run(self, learning_id: str, run_id: str | None) -> LearningRecord | None:
        with self._db.session() as session:
            service = LearningService(session)
            record = service.get(learning_id)
            return service.save(record.model_copy(update={"retry_run_id": run_id})) if record else None

    # ---------------------------------------------------------------- helpers
    def _build(self, incident: IncidentState, feedback: FeedbackType, reason: FailureReason | None,
               recommendation: Recommendation, now: datetime, result_override: dict[str, Any] | None = None,
               retry: tuple[int, str, str] | None = None) -> LearningRecord:
        v, r, t = incident.verification, incident.remediation, incident.triage
        runs = {name: run.run_id for name, run in (
            ("triage", t), ("investigation", incident.investigation), ("compliance", incident.compliance),
            ("remediation", r), ("verification", v)) if run is not None}
        providers = {name: f"{obj.provider}/{obj.model}" for name, obj in (
            ("triage", t), ("investigation", incident.investigation), ("compliance", incident.compliance),
            ("remediation", r)) if obj is not None and getattr(obj, "provider", None)}
        ml = getattr(incident, "ml_prediction", None)
        result = result_override if result_override is not None else ({} if v is None else {
            "expected_state": v.expected_state, "actual_state": v.actual_state, "failure_reason": v.failure_reason,
            "confidence": v.confidence, "reported_execution_status": v.reported_execution_status.value
            if v.reported_execution_status else None, "reason": v.reason[:300]})
        return LearningRecord(
            incident_id=incident.incident_id, timestamp=now, incident_category=incident.category.value,
            attack_type=(t.interpretation.classification if t else incident.event_type)[:255],
            initial_severity=(t.previous.severity if t else incident.severity).value, final_severity=incident.severity.value,
            initial_priority=t.previous.priority.value if t and t.previous.priority else None,
            final_priority=incident.priority.value if incident.priority else None, agent_run_ids=runs,
            remediation_action=v.action.value if v else (r.plan.action.value if r else None),
            remediation_target=v.target if v else (r.plan.target if r else None),
            verification_run_id=v.run_id if v else None, verification_status=v.status.value if v else None,
            verification_result=result, auto_feedback_type=feedback, feedback_type=feedback, failure_reason=reason,
            recommendation=recommendation, successful=feedback == FeedbackType.SUCCESSFUL_RESPONSE,
            retry_count=retry[0] if retry else 0, retry_limit=self._rules.retry_limit if retry else None,
            previous_run_id=retry[1] if retry else None, retry_reason=retry[2] if retry else None, providers=providers,
            ml_prediction=ml.prediction if ml else None, ml_features=dict(ml.features) if ml else None,
            ml_model_version=ml.model_version if ml else None)

    def _entry(self, now: datetime, incident_id: str, action: str, decision: str, result: str,
               record: LearningRecord) -> AuditEntry:
        return AuditEntry(timestamp=now, incident_id=incident_id, actor=HumanActor.SYSTEM, action=action,
                          decision=decision, result=result[:500], details={
                              "learning_id": record.learning_id, "feedback_type": record.feedback_type.value,
                              "verification_status": record.verification_status, "action": record.remediation_action,
                              "target": record.remediation_target,
                              "failure_reason": record.failure_reason.value if record.failure_reason else None,
                              "recommendation": record.recommendation.value, "service": SERVICE_LABEL})

    def _record_run(self, run: _Run) -> None:
        try:
            with self._db.session() as session:
                AgentRunService(session).record(AgentRunRecord(
                    run_id=run.run_id, agent=SERVICE_LABEL, incident_id=run.incident_id, started_at=run.now,
                    finished_at=self._clock(), status=run.status.value, outcome=run.outcome, method="deterministic",
                    provider=None, model=None, confidence=None,
                    result={"status": run.status.value, "outcome": run.outcome, "incident_id": run.incident_id,
                            "reasoning_summary": (run.records[0].feedback_type.value if run.records else ""),
                            "confidence": 0.0, "findings": [f"feedback:{r.feedback_type.value}" for r in run.records]
                            + [f"failure:{r.failure_reason.value}" for r in run.records if r.failure_reason],
                            "errors": run.errors}))
        except Exception:
            logger.exception("could not record feedback run %s", run.run_id)
