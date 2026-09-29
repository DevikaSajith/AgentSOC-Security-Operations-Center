"""Persistence for Monitor Agent bookkeeping: processed-event ledger and run history."""

from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.models import EventRecord, MonitorLedgerRecord, MonitorRunRecord
from app.domain.events import SecurityEvent
from app.services.errors import raise_storage_error
from app.services.event_service import to_event

_CHUNK = 500  # keep IN (...) lists well below database parameter limits


def _chunks(values: list[str]) -> Iterable[list[str]]:
    for start in range(0, len(values), _CHUNK):
        yield values[start:start + _CHUNK]


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class MonitorLedgerService:
    def __init__(self, session: Session) -> None:
        self._session = session

    # ----------------------------------------------------------------- reads
    def processed_event_ids(self, event_ids: Iterable[str]) -> set[str]:
        found: set[str] = set()
        for chunk in _chunks(list(set(event_ids))):
            found.update(self._scalars(select(MonitorLedgerRecord.event_id)
                                   .where(MonitorLedgerRecord.event_id.in_(chunk))))
        return found

    def fingerprint_owners(self, fingerprints: Iterable[str]) -> dict[str, str]:
        """fingerprint -> event_id of the first processed event with that fingerprint."""
        owners: dict[str, str] = {}
        for chunk in _chunks(list(set(fingerprints))):
            rows = self._rows(select(MonitorLedgerRecord.fingerprint, MonitorLedgerRecord.event_id)
                              .where(MonitorLedgerRecord.fingerprint.in_(chunk))
                              .order_by(MonitorLedgerRecord.id))
            for fp, event_id in rows:
                owners.setdefault(fp, event_id)
        return owners

    def unprocessed_events(self, since: datetime | None, limit: int) -> list[SecurityEvent]:
        """Stored events never seen by the Monitor, oldest first (uses the ledger index)."""
        stmt = (select(EventRecord)
                .outerjoin(MonitorLedgerRecord, MonitorLedgerRecord.event_id == EventRecord.event_id)
                .where(MonitorLedgerRecord.id.is_(None))
                .order_by(EventRecord.timestamp.asc()).limit(limit))
        if since is not None:
            stmt = stmt.where(EventRecord.timestamp >= since)
        return [to_event(r) for r in self._scalars(stmt)]

    def stats(self) -> dict[str, Any]:
        totals = self._rows(select(
            func.count(MonitorRunRecord.id), func.coalesce(func.sum(MonitorRunRecord.events_processed), 0),
            func.coalesce(func.sum(MonitorRunRecord.incidents_created), 0),
            func.coalesce(func.sum(MonitorRunRecord.incidents_updated), 0),
            func.coalesce(func.sum(MonitorRunRecord.events_rejected), 0),
            func.coalesce(func.sum(MonitorRunRecord.duplicates), 0)))[0]
        last = self._scalars(select(MonitorRunRecord).order_by(MonitorRunRecord.id.desc()).limit(1))
        last_run = last[0] if last else None
        return {
            "runs": totals[0], "events_processed": totals[1], "incidents_created": totals[2],
            "incidents_updated": totals[3], "events_rejected": totals[4], "duplicates": totals[5],
            "last_run_at": _utc(last_run.finished_at).isoformat() if last_run else None,
            "last_result": last_run.result if last_run else None,
        }

    # ---------------------------------------------------------------- writes
    def record_run(self, ledger: list[MonitorLedgerRecord], run: MonitorRunRecord) -> None:
        """Ledger rows and the run record, committed together."""
        try:
            self._session.add_all([*ledger, run])
            self._session.commit()
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise_storage_error(exc)

    # ------------------------------------------------------------- internals
    def _execute(self, stmt: Any) -> Any:
        try:
            return self._session.execute(stmt)
        except SQLAlchemyError as exc:
            raise_storage_error(exc)

    def _scalars(self, stmt: Any) -> list[Any]:
        return list(self._execute(stmt).scalars().all())

    def _rows(self, stmt: Any) -> list[Any]:
        return list(self._execute(stmt).all())
