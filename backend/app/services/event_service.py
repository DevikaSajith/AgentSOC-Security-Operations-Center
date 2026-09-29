"""Event persistence and queries (SQLAlchemy only)."""

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError
from sqlalchemy import distinct, func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.models import EventRecord
from app.domain.events import SecurityEvent
from app.services.errors import DatabaseUnavailableError, EventStorageError, raise_storage_error
from app.simulator.events import InvalidEventError

logger = logging.getLogger(__name__)

__all__ = ["DatabaseUnavailableError", "EventService", "EventStorageError"]


def _to_record(event: SecurityEvent) -> EventRecord:
    return EventRecord(
        event_id=event.event_id, timestamp=event.timestamp, source=event.source.value,
        account_id=event.account_id, region=event.region, event_type=event.event_type,
        user=event.user, source_ip=event.source_ip, resource_type=event.resource_type,
        resource_id=event.resource_id, action=event.action, severity=event.severity.value,
        details=event.details, raw_event=event.raw_event,
    )


def to_event(record: EventRecord) -> SecurityEvent:
    return SecurityEvent(
        event_id=record.event_id, timestamp=record.timestamp, source=record.source,
        account_id=record.account_id, region=record.region, event_type=record.event_type,
        user=record.user, source_ip=record.source_ip, resource_type=record.resource_type,
        resource_id=record.resource_id, action=record.action, severity=record.severity,
        details=record.details or {}, raw_event=record.raw_event or {},
    )


def _coerce(event: SecurityEvent | dict[str, Any]) -> SecurityEvent:
    """Accept a SecurityEvent or a dict; reject anything invalid."""
    if isinstance(event, SecurityEvent):
        return event
    try:
        return SecurityEvent.model_validate(event)
    except ValidationError as exc:
        raise InvalidEventError(str(exc)) from exc


def _as_utc(value: datetime) -> datetime:
    # SQLite returns naive datetimes; everything is stored in UTC.
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class EventService:
    """Save and query events. One instance wraps one SQLAlchemy session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # ----------------------------------------------------------------- writes
    def save_event(self, event: SecurityEvent | dict[str, Any]) -> SecurityEvent:
        """Validate and store one event."""
        return self.save_events([event])[0]

    def save_events(self, events: list[SecurityEvent | dict[str, Any]]) -> list[SecurityEvent]:
        """Validate and store events atomically (all or none)."""
        valid = [_coerce(e) for e in events]
        try:
            self._session.add_all([_to_record(e) for e in valid])
            self._session.commit()
        except IntegrityError as exc:
            self._session.rollback()
            logger.error("event save failed: duplicate or invalid row")
            raise EventStorageError("could not save events (duplicate event_id?)") from exc
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise_storage_error(exc)
        for event in valid:
            logger.info("event saved: %s %s", event.event_type, event.event_id)
        return valid

    # ------------------------------------------------------------------ reads
    def get_recent_events(self, limit: int = 50) -> list[SecurityEvent]:
        """Newest events first."""
        return self.list_events(limit=limit)

    def get_events_by_user(self, user: str, limit: int = 100) -> list[SecurityEvent]:
        """Events for one user, newest first."""
        return self.list_events(user=user, limit=limit)

    def get_events_by_type(self, event_type: str, limit: int = 100) -> list[SecurityEvent]:
        """Events of one type, newest first."""
        return self.list_events(event_type=event_type, limit=limit)

    def get_events_by_time_range(self, start: datetime, end: datetime) -> list[SecurityEvent]:
        """Events with start <= timestamp <= end, oldest first."""
        stmt = (select(EventRecord)
                .where(EventRecord.timestamp >= start, EventRecord.timestamp <= end)
                .order_by(EventRecord.timestamp.asc()))
        return [to_event(r) for r in self._scalars(stmt)]

    def get_event(self, event_id: str) -> SecurityEvent | None:
        """One event by its event_id, or None."""
        stmt = select(EventRecord).where(EventRecord.event_id == event_id)
        records = self._scalars(stmt)
        return to_event(records[0]) if records else None

    def get_events_by_ids(self, event_ids: list[str]) -> list[SecurityEvent]:
        """Stored events with these IDs (unknown IDs are simply absent), oldest first."""
        found: list[SecurityEvent] = []
        unique = list(dict.fromkeys(event_ids))
        for start in range(0, len(unique), 500):
            stmt = (select(EventRecord).where(EventRecord.event_id.in_(unique[start:start + 500]))
                    .order_by(EventRecord.timestamp.asc()))
            found.extend(to_event(r) for r in self._scalars(stmt))
        return sorted(found, key=lambda e: e.timestamp)

    def list_events(self, user: str | None = None, event_type: str | None = None,
                    limit: int = 100, *, source: str | None = None,
                    severity: str | None = None,
                    resource_id: str | None = None) -> list[SecurityEvent]:
        """Filtered events, newest first."""
        stmt = select(EventRecord).order_by(EventRecord.timestamp.desc()).limit(limit)
        filters = ((EventRecord.user, user), (EventRecord.event_type, event_type),
                   (EventRecord.source, source), (EventRecord.severity, severity),
                   (EventRecord.resource_id, resource_id))
        for column, value in filters:
            if value:
                stmt = stmt.where(column == value)
        return [to_event(r) for r in self._scalars(stmt)]

    def count_events(self) -> int:
        """Total stored events."""
        return self._scalar(select(func.count(EventRecord.id))) or 0

    def get_stats(self, now: datetime | None = None) -> dict[str, Any]:
        """Aggregate statistics for GET /api/events/stats."""
        now = now or datetime.now(timezone.utc)
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        latest = self._scalar(select(func.max(EventRecord.timestamp)))
        return {
            "total_events": self.count_events(),
            "events_today": self._scalar(
                select(func.count(EventRecord.id)).where(EventRecord.timestamp >= day_start)) or 0,
            "users_with_events": self._scalar(
                select(func.count(distinct(EventRecord.user)))) or 0,
            "event_types": self._count_by(EventRecord.event_type),
            "by_source": self._count_by(EventRecord.source),
            "by_severity": self._count_by(EventRecord.severity),
            "latest_event_at": _as_utc(latest).isoformat() if latest else None,
        }

    # -------------------------------------------------------------- internals
    def _count_by(self, column: Any) -> dict[str, int]:
        rows = self._execute(select(column, func.count(EventRecord.id)).group_by(column)).all()
        return {name: count for name, count in rows}

    def _execute(self, stmt: Any) -> Any:
        try:
            return self._session.execute(stmt)
        except SQLAlchemyError as exc:
            raise_storage_error(exc)

    def _scalars(self, stmt: Any) -> list[EventRecord]:
        return list(self._execute(stmt).scalars().all())

    def _scalar(self, stmt: Any) -> Any:
        return self._execute(stmt).scalar()
