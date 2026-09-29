"""Append-only audit trail. Entries are written, never updated or deleted."""

import logging
from datetime import timezone

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.models import AuditLogRecord
from app.domain.incident import AuditEntry
from app.services.errors import raise_storage_error

logger = logging.getLogger(__name__)


def _to_entry(record: AuditLogRecord) -> AuditEntry:
    timestamp = record.timestamp
    if timestamp.tzinfo is None:  # SQLite drops tzinfo; values are stored in UTC
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return AuditEntry(
        audit_id=record.audit_id, timestamp=timestamp, incident_id=record.incident_id,
        actor=record.agent, action=record.action, decision=record.decision,
        result=record.result, reasoning=record.reasoning or "", confidence=record.confidence,
        tool_name=record.tool_name, details=record.details or {},
    )


class AuditService:
    """Record and list audit entries. One instance wraps one SQLAlchemy session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def record(self, entry: AuditEntry) -> AuditEntry:
        """Persist one entry."""
        try:
            self._session.add(AuditLogRecord(
                audit_id=entry.audit_id, incident_id=entry.incident_id,
                agent=entry.actor.value, action=entry.action, decision=entry.decision,
                result=entry.result, reasoning=entry.reasoning, confidence=entry.confidence,
                tool_name=entry.tool_name, details=entry.details, timestamp=entry.timestamp,
            ))
            self._session.commit()
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise_storage_error(exc)
        logger.info("audit: %s %s -> %s", entry.actor.value, entry.action, entry.result)
        return entry

    def list_entries(self, incident_id: str | None = None, limit: int = 200) -> list[AuditEntry]:
        """Entries, newest first."""
        stmt = select(AuditLogRecord).order_by(AuditLogRecord.timestamp.desc()).limit(limit)
        if incident_id:
            stmt = stmt.where(AuditLogRecord.incident_id == incident_id)
        try:
            return [_to_entry(r) for r in self._session.scalars(stmt).all()]
        except SQLAlchemyError as exc:
            raise_storage_error(exc)
