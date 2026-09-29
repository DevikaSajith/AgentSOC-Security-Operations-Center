"""
AgentSOC — SQLite Database Layer

Uses SQLAlchemy with SQLite for persistence. Stores:
- Incidents
- CloudEvents
- AuditEntries
- ApprovalRequests
- RemediationResults
- AgentState snapshots (for workflow resume)
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Float,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)

# ============================================================
# Engine Setup
# ============================================================

def get_db_path() -> str:
    return os.environ.get("SQLITE_DB_PATH", "./agentsoc.db")


def create_db_engine():
    db_path = get_db_path()
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    return engine


_engine = None
_SessionLocal = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_db_engine()
    return _engine


def get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionLocal


def get_db() -> Session:
    """FastAPI dependency for DB sessions."""
    SessionLocal = get_session_factory()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================
# ORM Models
# ============================================================

class Base(DeclarativeBase):
    pass


class IncidentORM(Base):
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    severity = Column(String, default="unknown")
    confidence = Column(Float, default=0.0)
    incident_type = Column(String, default="")
    source = Column(String, default="CloudTrail")
    resource = Column(String, default="")
    user = Column(String, default="")
    source_ip = Column(String, default="unknown")
    status = Column(String, default="Detecting")
    current_agent = Column(String, default="MonitorAgent")
    created = Column(String, default="")
    updated = Column(String, default="")
    description = Column(Text, default="")
    reasoning = Column(Text, default="")
    recommended_next_step = Column(String, default="investigate")
    # JSON fields
    related_event_ids = Column(JSON, default=list)
    triage_result = Column(JSON, nullable=True)
    investigation_result = Column(JSON, nullable=True)
    compliance_result = Column(JSON, nullable=True)
    remediation_result = Column(JSON, nullable=True)
    # Workflow state for resume
    workflow_state = Column(JSON, nullable=True)
    approval_required = Column(Boolean, default=False)
    approval_id = Column(String, nullable=True)


class CloudEventORM(Base):
    __tablename__ = "cloud_events"

    event_id = Column(String, primary_key=True)
    timestamp = Column(String, nullable=False)
    source = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    user = Column(String, nullable=False)
    resource = Column(String, default="")
    source_ip = Column(String, default="unknown")
    region = Column(String, default="us-east-1")
    parameters = Column(JSON, default=dict)
    severity_hint = Column(String, default="unknown")
    incident_id = Column(String, nullable=True)
    raw = Column(JSON, default=dict)


class AuditEntryORM(Base):
    __tablename__ = "audit_log"

    audit_id = Column(String, primary_key=True)
    timestamp = Column(String, nullable=False)
    incident_id = Column(String, nullable=True)
    agent = Column(String, nullable=False)
    action = Column(String, nullable=False)
    reasoning = Column(Text, default="")
    confidence = Column(Float, default=0.0)
    input_summary = Column(Text, default="")
    tool_used = Column(String, nullable=True)
    tool_result = Column(JSON, nullable=True)
    decision = Column(String, default="")
    result = Column(String, default="")


class ApprovalORM(Base):
    __tablename__ = "approvals"

    approval_id = Column(String, primary_key=True)
    incident_id = Column(String, nullable=False)
    action = Column(String, nullable=False)
    resource = Column(String, default="")
    reason = Column(Text, default="")
    requested_by = Column(String, nullable=False)
    risk = Column(String, default="medium")
    status = Column(String, default="Pending")
    policy_id = Column(String, default="")
    created = Column(String, default="")
    decided_by = Column(String, nullable=True)
    decided_at = Column(String, nullable=True)


class SimulatedCloudStateORM(Base):
    """Tracks the simulated cloud environment state for verification."""
    __tablename__ = "simulated_state"

    resource_id = Column(String, primary_key=True)
    resource_type = Column(String, nullable=False)  # "iam_access_key", "s3_bucket", "ec2_instance"
    state = Column(JSON, nullable=False)  # {"enabled": true} / {"public": false} / etc.
    updated = Column(String, default="")


# ============================================================
# Init DB
# ============================================================

def init_db():
    """Create all tables if they don't exist."""
    engine = get_engine()
    Base.metadata.create_all(engine)
    logger.info("Database initialized at %s", get_db_path())
    _seed_simulated_state()


def _seed_simulated_state():
    """Seed the simulated cloud state with initial resource states."""
    SessionLocal = get_session_factory()
    db = SessionLocal()
    try:
        # Only seed if empty
        if db.query(SimulatedCloudStateORM).count() > 0:
            return

        resources = [
            SimulatedCloudStateORM(
                resource_id="key_alice_001",
                resource_type="iam_access_key",
                state={"enabled": True, "user": "alice", "created_at": "2025-01-01T00:00:00"},
                updated=datetime.utcnow().isoformat(),
            ),
            SimulatedCloudStateORM(
                resource_id="key_m_ortiz_001",
                resource_type="iam_access_key",
                state={"enabled": True, "user": "m.ortiz", "created_at": "2025-01-01T00:00:00"},
                updated=datetime.utcnow().isoformat(),
            ),
            SimulatedCloudStateORM(
                resource_id="key_ci_deploy_001",
                resource_type="iam_access_key",
                state={"enabled": True, "user": "ci-deploy", "created_at": "2025-01-15T00:00:00"},
                updated=datetime.utcnow().isoformat(),
            ),
            SimulatedCloudStateORM(
                resource_id="acme-prod-exports",
                resource_type="s3_bucket",
                state={"public": True, "public_access_block": False, "region": "us-east-1"},
                updated=datetime.utcnow().isoformat(),
            ),
            SimulatedCloudStateORM(
                resource_id="i-0a73c9f8d2e1b4a9c",
                resource_type="ec2_instance",
                state={"running": True, "security_groups": ["sg-normal-001"], "quarantined": False},
                updated=datetime.utcnow().isoformat(),
            ),
            SimulatedCloudStateORM(
                resource_id="user_ci-deploy",
                resource_type="iam_user",
                state={"policies": ["ReadOnlyAccess"], "admin_attached": False},
                updated=datetime.utcnow().isoformat(),
            ),
        ]

        for r in resources:
            db.add(r)
        db.commit()
        logger.info("Seeded %d simulated cloud resources", len(resources))
    except Exception as e:
        logger.error("Error seeding simulated state: %s", e)
        db.rollback()
    finally:
        db.close()


# ============================================================
# Repository helpers
# ============================================================

class IncidentRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, incident: "IncidentORM") -> "IncidentORM":
        self.db.add(incident)
        self.db.commit()
        self.db.refresh(incident)
        return incident

    def get(self, incident_id: str) -> Optional["IncidentORM"]:
        return self.db.query(IncidentORM).filter(
            IncidentORM.incident_id == incident_id
        ).first()

    def list_all(self) -> List["IncidentORM"]:
        return self.db.query(IncidentORM).order_by(IncidentORM.created.desc()).all()

    def update(self, incident_id: str, updates: Dict[str, Any]) -> Optional["IncidentORM"]:
        obj = self.get(incident_id)
        if not obj:
            return None
        for k, v in updates.items():
            setattr(obj, k, v)
        obj.updated = datetime.utcnow().isoformat()
        self.db.commit()
        self.db.refresh(obj)
        return obj


class AuditRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, entry: "AuditEntryORM") -> "AuditEntryORM":
        self.db.add(entry)
        self.db.commit()
        return entry

    def list_all(self) -> List["AuditEntryORM"]:
        return self.db.query(AuditEntryORM).order_by(AuditEntryORM.timestamp.desc()).all()

    def list_by_incident(self, incident_id: str) -> List["AuditEntryORM"]:
        return self.db.query(AuditEntryORM).filter(
            AuditEntryORM.incident_id == incident_id
        ).all()


class ApprovalRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, approval: "ApprovalORM") -> "ApprovalORM":
        self.db.add(approval)
        self.db.commit()
        self.db.refresh(approval)
        return approval

    def get(self, approval_id: str) -> Optional["ApprovalORM"]:
        return self.db.query(ApprovalORM).filter(
            ApprovalORM.approval_id == approval_id
        ).first()

    def get_by_incident(self, incident_id: str) -> Optional["ApprovalORM"]:
        return self.db.query(ApprovalORM).filter(
            ApprovalORM.incident_id == incident_id
        ).order_by(ApprovalORM.created.desc()).first()

    def list_pending(self) -> List["ApprovalORM"]:
        return self.db.query(ApprovalORM).filter(
            ApprovalORM.status == "Pending"
        ).all()

    def list_all(self) -> List["ApprovalORM"]:
        return self.db.query(ApprovalORM).order_by(ApprovalORM.created.desc()).all()

    def update_status(self, approval_id: str, status: str, decided_by: str = "analyst") -> Optional["ApprovalORM"]:
        obj = self.get(approval_id)
        if not obj:
            return None
        obj.status = status
        obj.decided_by = decided_by
        obj.decided_at = datetime.utcnow().isoformat()
        self.db.commit()
        return obj


class EventRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_many(self, events: List["CloudEventORM"]) -> None:
        for e in events:
            self.db.add(e)
        self.db.commit()

    def list_all(self) -> List["CloudEventORM"]:
        return self.db.query(CloudEventORM).order_by(
            CloudEventORM.timestamp.desc()
        ).limit(200).all()

    def list_by_user(self, user: str) -> List["CloudEventORM"]:
        return self.db.query(CloudEventORM).filter(
            CloudEventORM.user == user
        ).all()

    def list_by_incident(self, incident_id: str) -> List["CloudEventORM"]:
        return self.db.query(CloudEventORM).filter(
            CloudEventORM.incident_id == incident_id
        ).all()


class SimulatedStateRepository:
    def __init__(self, db: Session):
        self.db = db

    def get(self, resource_id: str) -> Optional["SimulatedCloudStateORM"]:
        return self.db.query(SimulatedCloudStateORM).filter(
            SimulatedCloudStateORM.resource_id == resource_id
        ).first()

    def update_state(self, resource_id: str, new_state: Dict[str, Any]) -> Optional["SimulatedCloudStateORM"]:
        obj = self.get(resource_id)
        if not obj:
            return None
        obj.state = new_state
        obj.updated = datetime.utcnow().isoformat()
        self.db.commit()
        return obj

    def list_all(self) -> List["SimulatedCloudStateORM"]:
        return self.db.query(SimulatedCloudStateORM).all()
