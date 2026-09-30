"""Approval requests for remediation proposals. One row = one exact proposal; a decision on one row
can never authorize a different action, target or incident."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.models import ApprovalRecord
from app.domain.events import utcnow
from app.domain.remediation import ApprovalState
from app.services.errors import raise_storage_error


def proposal_hash(incident_id: str, action: str, target: str, arguments: dict[str, Any]) -> str:
    canonical = json.dumps({"incident": incident_id, "action": action, "target": target,
                            "arguments": arguments}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class ApprovalView(BaseModel):
    approval_id: str
    incident_id: str
    agent_run_id: str
    action: str
    target: str
    arguments: dict[str, Any]
    reason: str
    risk: str
    evidence_ids: list[str]
    expected_effect: str
    status: ApprovalState
    requested_at: datetime
    expires_at: datetime
    reviewed_at: datetime | None
    reviewed_by: str | None
    decision: str | None
    executed_at: datetime | None
    proposal_hash: str

    @property
    def is_tampered(self) -> bool:
        return self.proposal_hash != proposal_hash(self.incident_id, self.action, self.target, self.arguments)


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:  # SQLite drops tzinfo; values are UTC
        return value.replace(tzinfo=timezone.utc)
    return value


def _view(r: ApprovalRecord) -> ApprovalView:
    return ApprovalView(
        approval_id=r.approval_id, incident_id=r.incident_id, agent_run_id=r.agent_run_id, action=r.action,
        target=r.target, arguments=r.arguments or {}, reason=r.reason, risk=r.risk,
        evidence_ids=list(r.evidence_ids or []), expected_effect=r.expected_effect,
        status=ApprovalState(r.status), requested_at=_aware(r.requested_at), expires_at=_aware(r.expires_at),
        reviewed_at=_aware(r.reviewed_at), reviewed_by=r.reviewed_by, decision=r.decision,
        executed_at=_aware(r.executed_at), proposal_hash=r.proposal_hash)


class ApprovalService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def _commit(self) -> None:
        try:
            self._session.commit()
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise_storage_error(exc)

    def _expire_due(self, record: ApprovalRecord, now: datetime) -> None:
        """Pending and approved-but-unexecuted requests both lapse at expires_at."""
        open_states = (ApprovalState.PENDING.value, ApprovalState.APPROVED.value)
        if record.status in open_states and record.executed_at is None and _aware(record.expires_at) <= now:
            record.status = ApprovalState.EXPIRED.value
            record.reviewed_at, record.reviewed_by = now, "System"
            record.decision = "approval expired before the action was executed"
            self._commit()

    def create(self, *, incident_id: str, agent_run_id: str, action: str, target: str,
               arguments: dict[str, Any], reason: str, risk: str, evidence_ids: list[str],
               expected_effect: str, expires_at: datetime, requested_at: datetime | None = None) -> ApprovalView:
        record = ApprovalRecord(
            approval_id=f"APR-{uuid4().hex[:10].upper()}", incident_id=incident_id, agent_run_id=agent_run_id,
            action=action, target=target, arguments=arguments, reason=reason, risk=risk,
            evidence_ids=evidence_ids, expected_effect=expected_effect, expires_at=expires_at,
            proposal_hash=proposal_hash(incident_id, action, target, arguments),
            status=ApprovalState.PENDING.value, requested_at=requested_at or utcnow())
        self._session.add(record)
        self._commit()
        return _view(record)

    def get(self, approval_id: str, now: datetime | None = None) -> ApprovalView | None:
        try:
            record = self._session.scalars(select(ApprovalRecord).where(
                ApprovalRecord.approval_id == approval_id)).first()
            if record is None:
                return None
            self._expire_due(record, now or utcnow())
        except SQLAlchemyError as exc:
            raise_storage_error(exc)
        return _view(record)

    def list(self, status: str | None = None, incident_id: str | None = None,
             limit: int = 200, now: datetime | None = None) -> list[ApprovalView]:
        stmt = (select(ApprovalRecord).order_by(ApprovalRecord.requested_at.desc(), ApprovalRecord.id.desc())
                .limit(limit))
        if incident_id:
            stmt = stmt.where(ApprovalRecord.incident_id == incident_id)
        try:
            records = self._session.scalars(stmt).all()
            for record in records:
                self._expire_due(record, now or utcnow())
        except SQLAlchemyError as exc:
            raise_storage_error(exc)
        return [_view(r) for r in records if status is None or r.status == status]

    def count(self, status: str) -> int:
        return len(self.list(status=status, limit=1000))

    def transition(self, approval_id: str, new_status: ApprovalState, *, allowed_from: tuple[ApprovalState, ...],
                   reviewed_by: str, decision: str | None, now: datetime | None = None) -> ApprovalView | None:
        """Move an approval to `new_status` only if it is currently one of `allowed_from`
        (returns None otherwise, so a decision cannot be applied twice)."""
        now = now or utcnow()
        try:
            record = self._session.scalars(select(ApprovalRecord).where(
                ApprovalRecord.approval_id == approval_id)).first()
            if record is None:
                return None
            self._expire_due(record, now)
            if ApprovalState(record.status) not in allowed_from:
                return None
            record.status = new_status.value
            record.reviewed_at, record.reviewed_by, record.decision = now, reviewed_by, decision
            self._commit()
        except SQLAlchemyError as exc:
            raise_storage_error(exc)
        return _view(record)

    def mark_executed(self, approval_id: str, when: datetime) -> None:
        record = self._session.scalars(select(ApprovalRecord).where(
            ApprovalRecord.approval_id == approval_id)).first()
        if record is not None:
            record.executed_at = when
            self._commit()

    def supersede_pending(self, incident_id: str, now: datetime | None = None) -> int:
        """A new proposal replaces older open ones for the same incident (they become expired)."""
        now = now or utcnow()
        count = 0
        for record in self._session.scalars(select(ApprovalRecord).where(
                ApprovalRecord.incident_id == incident_id,
                ApprovalRecord.status.in_((ApprovalState.PENDING.value, ApprovalState.APPROVED.value)),
                ApprovalRecord.executed_at.is_(None))).all():
            record.status, record.reviewed_at, record.reviewed_by = ApprovalState.EXPIRED.value, now, "System"
            record.decision = "superseded by a newer remediation proposal"
            count += 1
        self._commit()
        return count
