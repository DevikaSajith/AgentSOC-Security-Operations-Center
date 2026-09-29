"""Run history for incident-level agents (Triage) and the statistics shown in the UI."""

from datetime import timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.models import AgentRunRecord
from app.services.errors import raise_storage_error


class AgentRunService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def record(self, run: AgentRunRecord) -> None:
        try:
            self._session.add(run)
            self._session.commit()
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise_storage_error(exc)

    def stats(self, agent: str) -> dict[str, Any]:
        """runs / successful / failed / fallback counts and the last run, for one agent."""
        try:
            rows = self._session.execute(
                select(AgentRunRecord.status, func.count(AgentRunRecord.id))
                .where(AgentRunRecord.agent == agent).group_by(AgentRunRecord.status)).all()
            last = self._session.scalars(select(AgentRunRecord).where(AgentRunRecord.agent == agent)
                                         .order_by(AgentRunRecord.id.desc()).limit(1)).first()
            fallback = self._session.scalar(
                select(func.count(AgentRunRecord.id)).where(
                    AgentRunRecord.agent == agent, AgentRunRecord.method == "rule_based_fallback")) or 0
        except SQLAlchemyError as exc:
            raise_storage_error(exc)
        counts = {status: count for status, count in rows}
        finished = last.finished_at if last else None
        if finished is not None and finished.tzinfo is None:
            finished = finished.replace(tzinfo=timezone.utc)
        return {
            "runs": sum(counts.values()),
            "successful_runs": counts.get("success", 0),
            "failed_runs": counts.get("failed", 0),
            "fallback_runs": fallback,
            "last_run_at": finished.isoformat() if finished else None,
            "last_incident_id": last.incident_id if last else None,
            "last_provider": last.provider if last else None,
            "last_model": last.model if last else None,
            "last_result": last.result if last else None,
        }
