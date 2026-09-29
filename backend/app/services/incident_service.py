"""Incident persistence. Incidents are stored as full IncidentState documents.

This is the only incident write path; agents (currently the Monitor Agent) create and
update incidents through `save`.
"""

import logging
from datetime import datetime
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.models import IncidentRecord
from app.domain.events import utcnow
from app.domain.incident import IncidentState
from app.services.errors import raise_storage_error

logger = logging.getLogger(__name__)


class IncidentService:
    """Save and query incidents. One instance wraps one SQLAlchemy session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, incident: IncidentState) -> IncidentState:
        """Insert or update an incident. The state is re-validated, so a copy built with
        model_copy(update=...) cannot persist inconsistent data."""
        incident = IncidentState.model_validate({**incident.model_dump(), "updated_at": utcnow()})
        state = incident.model_dump(mode="json")
        try:
            record = self._session.scalars(select(IncidentRecord).where(
                IncidentRecord.incident_id == incident.incident_id)).first()
            if record is None:
                record = IncidentRecord(incident_id=incident.incident_id,
                                        created_at=incident.timestamp)
                self._session.add(record)
            record.status = incident.final_status.value
            record.severity = incident.severity.value
            record.title = incident.title
            record.state = state
            record.updated_at = incident.updated_at
            self._session.commit()
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise_storage_error(exc)
        logger.info("incident saved: %s (%s)", incident.incident_id, incident.final_status.value)
        return incident

    def get(self, incident_id: str) -> IncidentState | None:
        """One incident, or None."""
        try:
            record = self._session.scalars(select(IncidentRecord).where(
                IncidentRecord.incident_id == incident_id)).first()
        except SQLAlchemyError as exc:
            raise_storage_error(exc)
        return IncidentState.model_validate(record.state) if record else None

    def list_open_updated_since(self, since: datetime, closed_statuses: Iterable[str],
                                limit: int = 500) -> list[IncidentState]:
        """Open incidents updated at/after `since` (candidates for merging new activity)."""
        stmt = (select(IncidentRecord)
                .where(IncidentRecord.updated_at >= since,
                       IncidentRecord.status.not_in(list(closed_statuses)))
                .order_by(IncidentRecord.updated_at.desc()).limit(limit))
        try:
            records = self._session.scalars(stmt).all()
        except SQLAlchemyError as exc:
            raise_storage_error(exc)
        return [IncidentState.model_validate(r.state) for r in records]

    def list_incidents(self, status: str | None = None, severity: str | None = None,
                       limit: int = 100) -> list[IncidentState]:
        """Incidents, newest first."""
        stmt = select(IncidentRecord).order_by(IncidentRecord.created_at.desc()).limit(limit)
        if status:
            stmt = stmt.where(IncidentRecord.status == status)
        if severity:
            stmt = stmt.where(IncidentRecord.severity == severity)
        try:
            records = self._session.scalars(stmt).all()
        except SQLAlchemyError as exc:
            raise_storage_error(exc)
        return [IncidentState.model_validate(r.state) for r in records]
