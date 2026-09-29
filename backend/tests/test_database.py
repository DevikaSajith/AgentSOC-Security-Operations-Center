from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from app.config import DEFAULT_DATABASE_URL, get_settings
from app.database.connection import Database
from app.domain.enums import EventSource, HumanActor, IncidentStatus, Severity
from app.domain.incident import AuditEntry, IncidentState
from app.main import create_app
from app.services.audit_service import AuditService
from app.services.event_service import EventService, EventStorageError
from app.services.incident_service import IncidentService
from app.simulator.events import EventGenerator, InvalidEventError


# ---------------------------------------------------------------- configuration
def test_sqlite_is_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "")
    settings = get_settings()
    assert settings.database_url == DEFAULT_DATABASE_URL
    assert settings.database_backend == "sqlite"


def test_database_url_selects_postgresql(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@localhost:5432/agentsoc")
    assert get_settings().database_backend == "postgresql"


def test_sqlite_file_database_starts_up(tmp_path: Path) -> None:
    """A fresh SQLite file (in a folder that does not exist yet) gets all tables on startup."""
    db_file = tmp_path / "nested" / "agentsoc.db"
    database = Database.from_url(f"sqlite:///{db_file.as_posix()}")
    with TestClient(create_app(database=database)) as client:
        assert client.get("/api/healthz").json()["database"] == {"backend": "sqlite",
                                                                 "status": "ok"}
        assert client.post("/api/simulation/run",
                           json={"scenario": "credential_misuse"}).status_code == 200
    assert db_file.is_file()
    assert {"events", "incidents", "audit_log"} <= set(inspect(database.engine).get_table_names())
    # data survives a restart (new engine, same file)
    database.engine.dispose()
    with Database.from_url(f"sqlite:///{db_file.as_posix()}").session() as session:
        assert EventService(session).count_events() == 4


# ---------------------------------------------------------------------- events
def test_events_can_be_stored_and_queried(database: Database) -> None:
    gen = EventGenerator()
    events = [gen.create_event("Login", user="alice", source_ip="203.0.113.10"),
              gen.create_event("ListUsers", user="bob", source_ip="203.0.113.20")]
    with database.session() as session:
        service = EventService(session)
        service.save_events(events)
        assert service.count_events() == 2
        assert [e.user for e in service.get_events_by_user("alice")] == ["alice"]
        assert service.get_events_by_type("ListUsers")[0].event_id == events[1].event_id
        assert len(service.get_recent_events()) == 2
        stored = service.get_event(events[0].event_id)
        assert stored.details == events[0].details
        assert stored.raw_event == events[0].raw_event
        assert stored.source == EventSource.CLOUDTRAIL


def test_new_event_fields_round_trip_and_filter(database: Database) -> None:
    gen = EventGenerator()
    flow = gen.create_event("NetworkFlowAnomaly", user="bob", source_ip="203.0.113.20",
                            resource_id="ec2-001", details={"destination_port": 4444})
    login = gen.create_event("Login", user="bob", source_ip="203.0.113.20")
    with database.session() as session:
        service = EventService(session)
        service.save_events([flow, login])
        assert [e.event_id for e in service.list_events(source="VPC Flow Logs")] == [flow.event_id]
        assert [e.event_id for e in service.list_events(severity="high")] == [flow.event_id]
        assert [e.event_id for e in service.list_events(resource_id="ec2-001")] == [flow.event_id]
        stored = service.get_event(flow.event_id)
    assert stored.severity == Severity.HIGH and stored.region == "us-east-1"


def test_time_range_query(database: Database) -> None:
    gen = EventGenerator()
    now = datetime.now(timezone.utc)
    old = gen.create_event("Login", user="alice", source_ip="203.0.113.10",
                           timestamp=now - timedelta(hours=5))
    new = gen.create_event("Login", user="alice", source_ip="203.0.113.10", timestamp=now)
    with database.session() as session:
        service = EventService(session)
        service.save_events([old, new])
        found = service.get_events_by_time_range(now - timedelta(hours=1), now + timedelta(hours=1))
        assert [e.event_id for e in found] == [new.event_id]


def test_duplicate_event_id_rejected_atomically(database: Database) -> None:
    event = EventGenerator().create_event("Login", user="alice", source_ip="203.0.113.10")
    with database.session() as session:
        service = EventService(session)
        service.save_event(event)
        with pytest.raises(EventStorageError):
            service.save_event(event)
        assert service.count_events() == 1


def test_invalid_event_dict_rejected(database: Database) -> None:
    with database.session() as session:
        with pytest.raises(InvalidEventError):
            EventService(session).save_event({"event_type": "Login"})


def test_stats(database: Database) -> None:
    gen = EventGenerator()
    with database.session() as session:
        service = EventService(session)
        service.save_events([gen.create_event("Login", user="alice", source_ip="203.0.113.10"),
                             gen.create_event("Login", user="bob", source_ip="203.0.113.20")])
        stats = service.get_stats()
    assert stats["total_events"] == 2 and stats["users_with_events"] == 2
    assert stats["event_types"] == {"Login": 2}
    assert stats["by_source"] == {"CloudTrail": 2} and stats["by_severity"] == {"info": 2}
    assert stats["latest_event_at"] is not None


# ------------------------------------------------------------ incidents / audit
def test_incident_state_round_trips(database: Database) -> None:
    incident = IncidentState(title="Admin policy attached", source=EventSource.CLOUDTRAIL,
                             event_type="AttachAdminPolicy", principal_id="alice",
                             severity=Severity.HIGH)
    with database.session() as session:
        service = IncidentService(session)
        service.save(incident)
        service.save(incident.model_copy(update={"final_status": IncidentStatus.TRIAGING}))
        stored = service.get(incident.incident_id)
        assert [i.incident_id for i in service.list_incidents()] == [incident.incident_id]
        assert service.list_incidents(status="new") == []
    assert stored.final_status == IncidentStatus.TRIAGING and stored.principal_id == "alice"


def test_audit_entries_are_listed_newest_first(database: Database) -> None:
    with database.session() as session:
        service = AuditService(session)
        first = service.record(AuditEntry(actor=HumanActor.SYSTEM, action="a",
                                          timestamp=datetime.now(timezone.utc) - timedelta(1)))
        second = service.record(AuditEntry(actor=HumanActor.ANALYST, action="b"))
        entries = service.list_entries()
    assert [e.audit_id for e in entries] == [second.audit_id, first.audit_id]
    assert entries[0].actor == HumanActor.ANALYST
