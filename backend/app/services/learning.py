from __future__ import annotations

"""Historical learning store (SQLite/PostgreSQL through the existing SQLAlchemy layer). Plain SQL filters:
no vector database, no embeddings."""

from datetime import timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.models import AgentRunRecord, LearningRecordRow
from app.domain.enums import AgentName
from app.domain.learning import FeedbackType, LearningRecord
from app.services.errors import raise_storage_error


def _to_record(row: LearningRecordRow) -> LearningRecord:
    return LearningRecord.model_validate(row.payload)


class LearningService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, record: LearningRecord) -> LearningRecord:
        """Insert or update (by learning_id). The record is re-validated before it is stored."""
        record = LearningRecord.model_validate(record.model_dump())
        try:
            row = self._session.scalars(select(LearningRecordRow).where(
                LearningRecordRow.learning_id == record.learning_id)).first()
            if row is None:
                row = LearningRecordRow(learning_id=record.learning_id)
                self._session.add(row)
            row.incident_id, row.timestamp = record.incident_id, record.timestamp
            row.incident_category, row.attack_type = record.incident_category, record.attack_type[:255]
            row.remediation_action, row.verification_status = record.remediation_action, record.verification_status
            row.verification_run_id = record.verification_run_id
            row.failure_reason = record.failure_reason.value if record.failure_reason else None
            row.feedback_type, row.successful = record.feedback_type.value, record.successful
            row.human_feedback = record.human_feedback.value if record.human_feedback else None
            row.payload = record.model_dump(mode="json")
            self._session.commit()
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise_storage_error(exc)
        return record

    def get(self, learning_id: str) -> LearningRecord | None:
        try:
            row = self._session.scalars(select(LearningRecordRow).where(
                LearningRecordRow.learning_id == learning_id)).first()
        except SQLAlchemyError as exc:
            raise_storage_error(exc)
        return _to_record(row) if row else None

    def list(self, *, incident_category: str | None = None, attack_type: str | None = None,
             remediation_action: str | None = None, verification_status: str | None = None,
             failure_reason: str | None = None, feedback_type: str | None = None,
             incident_id: str | None = None, limit: int = 100) -> list[LearningRecord]:
        stmt = select(LearningRecordRow).order_by(LearningRecordRow.timestamp.desc(), LearningRecordRow.id.desc()).limit(limit)
        for column, value in ((LearningRecordRow.incident_category, incident_category),
                              (LearningRecordRow.attack_type, attack_type),
                              (LearningRecordRow.remediation_action, remediation_action),
                              (LearningRecordRow.verification_status, verification_status),
                              (LearningRecordRow.failure_reason, failure_reason),
                              (LearningRecordRow.feedback_type, feedback_type),
                              (LearningRecordRow.incident_id, incident_id)):
            if value:
                stmt = stmt.where(column == value)
        try:
            return [_to_record(r) for r in self._session.scalars(stmt).all()]
        except SQLAlchemyError as exc:
            raise_storage_error(exc)

    def for_incident(self, incident_id: str) -> list[LearningRecord]:
        return self.list(incident_id=incident_id, limit=500)

    def find(self, verification_run_id: str, feedback_type: FeedbackType) -> LearningRecord | None:
        try:
            row = self._session.scalars(select(LearningRecordRow).where(
                LearningRecordRow.verification_run_id == verification_run_id,
                LearningRecordRow.feedback_type == feedback_type.value)).first()
        except SQLAlchemyError as exc:
            raise_storage_error(exc)
        return _to_record(row) if row else None

    def retry_count(self, incident_id: str) -> int:
        return len(self.list(incident_id=incident_id, feedback_type=FeedbackType.RETRY_REQUESTED.value, limit=500))

    # ------------------------------------------------------------------ statistics
    def stats(self) -> dict[str, Any]:
        rows = self.list(limit=10000)
        outcome_rows = [r for r in rows if r.feedback_type not in (FeedbackType.RETRY_REQUESTED,)]
        by_type: dict[str, int] = {}
        for r in outcome_rows:
            by_type[r.feedback_type.value] = by_type.get(r.feedback_type.value, 0) + 1
        return {
            "total_learning_records": len(rows),
            "successful_responses": by_type.get("successful_response", 0),
            "failed_responses": by_type.get("failed_response", 0),
            "partial_responses": by_type.get("partial_response", 0),
            "insufficient_evidence": by_type.get("insufficient_evidence", 0),
            "regressions": sum(1 for r in rows if r.auto_feedback_type == FeedbackType.REGRESSION_DETECTED),
            "retry_requests": sum(1 for r in rows if r.feedback_type == FeedbackType.RETRY_REQUESTED),
            "human_corrections": sum(1 for r in rows if r.human_corrected),
            "human_feedback_given": sum(1 for r in rows if r.human_feedback is not None),
            "by_failure_reason": _count(r.failure_reason.value for r in rows if r.failure_reason),
            "by_remediation_action": _count(r.remediation_action for r in rows if r.remediation_action),
        }

    def agent_performance(self) -> dict[str, Any]:
        """Statistics from the existing agent_runs table only (nothing invented)."""
        try:
            runs = self._session.scalars(select(AgentRunRecord)).all()
        except SQLAlchemyError as exc:
            raise_storage_error(exc)
        agents: dict[str, dict[str, Any]] = {}
        for run in runs:
            a = agents.setdefault(run.agent, {"total_runs": 0, "successful_runs": 0, "failed_runs": 0,
                                              "partial_runs": 0, "skipped_runs": 0, "_seconds": 0.0})
            a["total_runs"] += 1
            key = {"success": "successful_runs", "failed": "failed_runs", "partial": "partial_runs",
                   "skipped": "skipped_runs"}.get(run.status)
            if key:
                a[key] += 1
            started, finished = run.started_at, run.finished_at
            if started and finished:
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                if finished.tzinfo is None:
                    finished = finished.replace(tzinfo=timezone.utc)
                a["_seconds"] += max(0.0, (finished - started).total_seconds())
        for a in agents.values():
            a["average_execution_time_seconds"] = round(a.pop("_seconds") / a["total_runs"], 3) if a["total_runs"] else None
        verdicts = [r.outcome for r in runs if r.agent == AgentName.VERIFICATION.value
                    and r.outcome in ("verified", "verification_failed", "verification_partial", "verification_unknown")]
        return {
            "agents": agents,
            "verification_success_rate": round(verdicts.count("verified") / len(verdicts), 4) if verdicts else None,
            "verification_runs_with_a_verdict": len(verdicts),
        }


def _count(values: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out
