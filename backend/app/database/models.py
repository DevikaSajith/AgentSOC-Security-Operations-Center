"""SQLAlchemy table definitions (portable across SQLite and PostgreSQL).

Schema migrations (Alembic) are not used yet: after changing a model, delete the SQLite
file (backend/agentsoc.db) or drop the tables so they are recreated.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.domain.events import utcnow

# JSONB on PostgreSQL, plain JSON elsewhere (SQLite).
JSONType = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    """Base class for all tables."""


class EventRecord(Base):
    """A stored security event (see app.domain.events.SecurityEvent)."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(50), index=True, default="CloudTrail")
    account_id: Mapped[str] = mapped_column(String(20), default="")
    region: Mapped[str] = mapped_column(String(30), default="")
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    user: Mapped[str] = mapped_column("user", String(100), index=True)
    source_ip: Mapped[str] = mapped_column(String(45))
    resource_type: Mapped[str] = mapped_column(String(100))
    resource_id: Mapped[str] = mapped_column(String(255), index=True)
    action: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20), index=True, default="info")
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IncidentRecord(Base):
    """A stored incident. `state` holds the full IncidentState; the other columns are
    copies of its most-queried fields so they can be filtered and sorted in SQL."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(50), index=True, default="new")
    severity: Mapped[str] = mapped_column(String(20), index=True, default="info")
    title: Mapped[str] = mapped_column(String(255), default="")
    state: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class MonitorLedgerRecord(Base):
    """One row per event the Monitor Agent has processed: makes runs idempotent and
    provides the fingerprint index used for deduplication."""

    __tablename__ = "monitor_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    outcome: Mapped[str] = mapped_column(String(30))  # incident_created/updated, no_incident, duplicate
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    duplicate_of: Mapped[str | None] = mapped_column(String(36), nullable=True)
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MonitorRunRecord(Base):
    """History of Monitor Agent runs (backs the agent's status/activity in the UI)."""

    __tablename__ = "monitor_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20))
    outcome: Mapped[str] = mapped_column(String(40))
    events_processed: Mapped[int] = mapped_column(Integer, default=0)
    events_rejected: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    incidents_created: Mapped[int] = mapped_column(Integer, default=0)
    incidents_updated: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)  # the AgentResult


class AgentRunRecord(Base):
    """One run of an incident-level agent (Triage today). The Monitor keeps its own
    batch-oriented monitor_runs table."""

    __tablename__ = "agent_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    agent: Mapped[str] = mapped_column(String(50), index=True)
    incident_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20))
    outcome: Mapped[str] = mapped_column(String(40))
    method: Mapped[str | None] = mapped_column(String(30), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(30), nullable=True)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    confidence: Mapped[float | None] = mapped_column(nullable=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)  # the AgentResult


class AuditLogRecord(Base):
    """Append-only audit trail (see app.domain.incident.AuditEntry)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    incident_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    agent: Mapped[str] = mapped_column(String(100))  # the actor (agent or human)
    action: Mapped[str] = mapped_column(String(100))
    decision: Mapped[str] = mapped_column(String(100), default="")
    result: Mapped[str] = mapped_column(Text, default="")
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float | None] = mapped_column(nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True,
                                                default=utcnow)


class ApprovalRecord(Base):
    """A human approval request for ONE exact remediation proposal (action + target + arguments).
    `proposal_hash` is computed when the request is created and re-checked before execution."""

    __tablename__ = "approvals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    approval_id: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    incident_id: Mapped[str] = mapped_column(String(36), index=True)
    agent_run_id: Mapped[str] = mapped_column(String(40))
    action: Mapped[str] = mapped_column(String(60))
    target: Mapped[str] = mapped_column(String(200))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    reason: Mapped[str] = mapped_column(Text, default="")
    risk: Mapped[str] = mapped_column(String(20))
    evidence_ids: Mapped[list[str]] = mapped_column(JSONType, default=list)
    expected_effect: Mapped[str] = mapped_column(Text, default="")
    proposal_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), index=True, default="pending")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    decision: Mapped[str | None] = mapped_column(Text, nullable=True)  # reviewer comment / system reason
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
