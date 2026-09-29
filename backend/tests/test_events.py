from datetime import datetime

import pytest

from app.domain.enums import EventSource, Severity
from app.domain.events import SIMULATED_ACCOUNT_ID, SecurityEvent
from app.simulator.attacks import AttackSimulator
from app.simulator.events import (
    NORMAL_EVENT_TYPES,
    SUSPICIOUS_IPS,
    EventGenerator,
    InvalidEventError,
)

REQUIRED = {"event_id", "timestamp", "source", "account_id", "region", "event_type", "user",
            "principal_id", "source_ip", "resource_type", "resource_id", "action", "severity",
            "details", "raw_event"}


def test_normal_events_are_generated() -> None:
    gen = EventGenerator()
    events = [gen.normal_event() for _ in range(30)]
    assert all(e.event_type in NORMAL_EVENT_TYPES for e in events)
    assert all(e.source_ip not in SUSPICIOUS_IPS for e in events)
    assert REQUIRED <= set(events[0].model_dump())


def test_event_ids_are_unique() -> None:
    gen = EventGenerator()
    ids = {gen.normal_event().event_id for _ in range(100)}
    assert len(ids) == 100


def test_normal_batch_is_time_ordered() -> None:
    events = EventGenerator().normal_batch(20)
    stamps = [e.timestamp for e in events]
    assert stamps == sorted(stamps)


def test_suspicious_event_uses_unusual_ip() -> None:
    assert EventGenerator().suspicious_event().source_ip in SUSPICIOUS_IPS


def test_unknown_event_type_rejected() -> None:
    with pytest.raises(InvalidEventError):
        EventGenerator().create_event("NopeEvent", user="alice", source_ip="203.0.113.10")


def test_invalid_ip_rejected() -> None:
    with pytest.raises(InvalidEventError):
        EventGenerator().create_event("Login", user="alice", source_ip="not-an-ip")


def test_naive_timestamp_becomes_utc() -> None:
    event = SecurityEvent(timestamp=datetime(2026, 1, 1), event_type="Login", user="a",
                          source_ip="203.0.113.1", resource_type="IAMUser",
                          resource_id="a", action="login")
    assert event.timestamp.tzinfo is not None


def test_phase1_shaped_event_gets_defaults() -> None:
    """Events without the new fields (old callers / old rows) still validate."""
    event = SecurityEvent(event_type="Login", user="alice", source_ip="203.0.113.10",
                          resource_type="IAMUser", resource_id="alice", action="login")
    assert event.source == EventSource.CLOUDTRAIL and event.severity == Severity.INFO
    assert event.account_id == SIMULATED_ACCOUNT_ID and event.principal_id == "alice"


def test_cloudtrail_raw_event_excludes_ground_truth(attacks: AttackSimulator) -> None:
    event = attacks.run("iam_privilege_escalation").events[1]  # CreateAccessKey
    raw = event.raw_event
    assert raw["eventName"] == "CreateAccessKey" and raw["eventID"] == event.event_id
    assert raw["sourceIPAddress"] == event.source_ip
    assert raw["userIdentity"]["userName"] == "alice"
    assert "scenario_id" in event.details  # ground truth stays in details...
    for key in ("scenario_id", "step", "state_change"):
        assert key not in raw["requestParameters"]  # ...never in what an agent would see


def test_network_anomaly_comes_from_vpc_flow_logs(attacks: AttackSimulator) -> None:
    flow = attacks.run("ec2_compromise").events[-1]
    assert flow.source == EventSource.VPC_FLOW_LOGS and flow.severity == Severity.HIGH
    assert flow.raw_event["dstport"] == 4444 and flow.raw_event["resource-id"] == "ec2-001"


def test_severity_is_a_static_api_rating() -> None:
    gen = EventGenerator()
    assert gen.create_event("ListUsers", user="bob", source_ip="203.0.113.20").severity \
        == Severity.INFO
    assert gen.create_event("AttachAdminPolicy", user="bob",
                            source_ip="203.0.113.20").severity == Severity.HIGH
