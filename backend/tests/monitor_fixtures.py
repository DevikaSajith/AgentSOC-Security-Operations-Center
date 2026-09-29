"""Shared builders for Monitor Agent tests. All records are SIMULATED sample data in the
shape of the corresponding AWS formats; none come from a real AWS account."""

from datetime import datetime, timedelta, timezone
from typing import Any

from app.agents.monitor.config import MonitorConfig, load_monitor_config
from app.agents.monitor.fingerprint import fingerprint
from app.agents.monitor.models import NormalizedEvent
from app.config import Settings
from app.domain.events import SecurityEvent
from app.simulator.events import EventGenerator

BASE_TIME = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=30)
ATTACKER_IP = "198.51.100.23"
ALICE_IP = "203.0.113.10"  # inside trusted_networks


def config() -> MonitorConfig:
    return load_monitor_config(Settings().config_dir)


def event(event_type: str, *, user: str = "alice", ip: str = ATTACKER_IP, at: float = 0,
          resource: str | None = None, **details: Any) -> SecurityEvent:
    """A simulator-generated event `at` seconds after BASE_TIME."""
    return EventGenerator().create_event(event_type, user=user, source_ip=ip,
                                         resource_id=resource,
                                         timestamp=BASE_TIME + timedelta(seconds=at),
                                         details=details or None)


def normalized(e: SecurityEvent) -> NormalizedEvent:
    return NormalizedEvent(event=e, fingerprint=fingerprint(e), ingest_format="security_event",
                           stored=True)


def iso(offset_seconds: float = 0) -> str:
    return (BASE_TIME + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


def cloudtrail(event_name: str, event_source: str, params: dict[str, Any], *,
               event_id: str = "ct-0001", user: str = "alice", ip: str = ATTACKER_IP,
               at: float = 0) -> dict[str, Any]:
    return {
        "eventVersion": "1.09", "eventID": event_id, "eventTime": iso(at),
        "eventSource": event_source, "eventName": event_name, "awsRegion": "us-east-1",
        "sourceIPAddress": ip, "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "userName": user, "accountId": "123456789012"},
        "requestParameters": params,
    }


def guardduty_finding(**overrides: Any) -> dict[str, Any]:
    finding = {
        "schemaVersion": "2.0", "id": "gd-finding-0001", "accountId": "123456789012",
        "region": "us-east-1", "type": "UnauthorizedAccess:EC2/TorClient", "severity": 8.0,
        "title": "Simulated finding", "updatedAt": iso(60),
        "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": "ec2-001"}},
        "service": {"action": {"networkConnectionAction": {
            "remoteIpDetails": {"ipAddressV4": "192.0.2.145"}}}},
    }
    return {**finding, **overrides}


def security_hub_finding(**overrides: Any) -> dict[str, Any]:
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational/v/1.0.0/S3.2/finding/0001",
        "AwsAccountId": "123456789012", "Region": "us-east-1",
        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
        "Title": "S3 bucket should prohibit public read access",
        "Severity": {"Label": "HIGH"}, "UpdatedAt": iso(90),
        "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::company-data"}],
    }
    return {**finding, **overrides}


def vpc_flow(**overrides: Any) -> dict[str, Any]:
    record = {"version": 2, "account-id": "123456789012", "resource-id": "ec2-001",
              "srcaddr": "10.0.1.10", "dstaddr": "198.51.100.200", "dstport": 4444,
              "bytes": 734003200, "action": "ACCEPT", "start": int(BASE_TIME.timestamp()) + 120}
    return {**record, **overrides}
