"""Security event generator (the SecurityEvent model lives in app.domain.events).

Events resemble cloud audit logs (CloudTrail-style) but are clearly SIMULATED.
IPs come from documentation-reserved ranges (RFC 5737), so they are never real hosts.
"""

import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable

from app.domain.enums import EventSource, Severity
from app.domain.events import DEFAULT_REGION, SIMULATED_ACCOUNT_ID, SecurityEvent, utcnow

__all__ = ["EventGenerator", "InvalidEventError", "SecurityEvent", "TEMPLATES"]

logger = logging.getLogger(__name__)

KNOWN_USER_IPS: dict[str, str] = {"alice": "203.0.113.10", "bob": "203.0.113.20"}
SUSPICIOUS_IPS: list[str] = ["198.51.100.77", "198.51.100.23", "192.0.2.145"]
BUCKETS: list[str] = ["company-data", "public-assets"]
INSTANCES: list[str] = ["ec2-001", "ec2-002"]
SAMPLE_OBJECT_KEYS: list[str] = ["reports/q1.pdf", "logo.png", "docs/handbook.pdf"]


class InvalidEventError(ValueError):
    """Raised when an event cannot be created or is malformed."""


@dataclass(frozen=True)
class EventTemplate:
    """Default fields for one event type.

    `severity` is a static sensitivity rating of the API call, as a detection source
    would attach it. It is not a triage verdict (that is the Triage Agent's job).
    """

    resource_type: str
    action: str
    resource_id: str | None = None  # None -> chosen per event
    details: dict[str, Any] = field(default_factory=dict)
    service: str = "iam.amazonaws.com"  # AWS service that would have logged the call
    source: EventSource = EventSource.CLOUDTRAIL
    severity: Severity = Severity.INFO


TEMPLATES: dict[str, EventTemplate] = {
    # --- normal activity
    "Login": EventTemplate("IAMUser", "login", details={"login_result": "success"},
                           service="signin.amazonaws.com"),
    "ListBuckets": EventTemplate("S3Bucket", "list_buckets", "*", service="s3.amazonaws.com"),
    "DescribeInstances": EventTemplate("EC2Instance", "describe_instances", "*",
                                       service="ec2.amazonaws.com"),
    "GetObject": EventTemplate("S3Bucket", "get_object", service="s3.amazonaws.com"),
    "ListUsers": EventTemplate("IAMUser", "list_users", "*"),
    "GetCallerIdentity": EventTemplate("IAMUser", "get_caller_identity",
                                       service="sts.amazonaws.com"),
    # --- suspicious activity
    "CreateAccessKey": EventTemplate("IAMUser", "create_access_key",
                                     details={"key_type": "programmatic"},
                                     severity=Severity.MEDIUM),
    "AttachAdminPolicy": EventTemplate("IAMUser", "attach_admin_policy",
                                       details={"policy": "AdministratorAccess"},
                                       severity=Severity.HIGH),
    "GetSecretValue": EventTemplate("Secret", "get_secret_value", "prod/db-password",
                                    service="secretsmanager.amazonaws.com",
                                    severity=Severity.MEDIUM),
    "PutBucketPolicy": EventTemplate("S3Bucket", "put_bucket_policy",
                                     details={"principal": "*", "effect": "Allow"},
                                     service="s3.amazonaws.com", severity=Severity.MEDIUM),
    "AuthorizeSecurityGroupIngress": EventTemplate(
        "SecurityGroup", "authorize_security_group_ingress", "sg-web",
        {"cidr": "0.0.0.0/0", "port": 22}, service="ec2.amazonaws.com",
        severity=Severity.MEDIUM),
    # --- used by attack scenarios
    "DeletePublicAccessBlock": EventTemplate("S3Bucket", "delete_public_access_block",
                                             service="s3.amazonaws.com", severity=Severity.HIGH),
    "ExecuteCommand": EventTemplate("EC2Instance", "execute_command",
                                    service="ssm.amazonaws.com", severity=Severity.MEDIUM),
    "AssumeRole": EventTemplate("EC2Instance", "assume_role", service="sts.amazonaws.com",
                                severity=Severity.MEDIUM),
    "NetworkFlowAnomaly": EventTemplate("EC2Instance", "network_flow_anomaly",
                                        service="vpc-flow-logs",
                                        source=EventSource.VPC_FLOW_LOGS,
                                        severity=Severity.HIGH),
}

# Keys in `details` that are simulator ground truth; never copied into raw_event.
GROUND_TRUTH_KEYS = frozenset({"scenario_id", "step", "state_change"})

NORMAL_EVENT_TYPES = ["Login", "ListBuckets", "DescribeInstances", "GetObject",
                      "ListUsers", "GetCallerIdentity"]
SUSPICIOUS_EVENT_TYPES = ["Login", "CreateAccessKey", "AttachAdminPolicy", "GetSecretValue",
                          "PutBucketPolicy", "AuthorizeSecurityGroupIngress"]


class EventGenerator:
    """Creates individual normal, suspicious, or custom events."""

    def __init__(
        self,
        rng: random.Random | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._rng = rng or random.Random()
        self._clock = clock

    def create_event(
        self,
        event_type: str,
        *,
        user: str,
        source_ip: str,
        resource_id: str | None = None,
        timestamp: datetime | None = None,
        details: dict[str, Any] | None = None,
    ) -> SecurityEvent:
        """Build an event from a template, with optional overrides."""
        template = TEMPLATES.get(event_type)
        if template is None:
            raise InvalidEventError(f"unknown event type '{event_type}'")
        try:
            event = SecurityEvent(
                timestamp=timestamp or self._clock(),
                source=template.source,
                account_id=SIMULATED_ACCOUNT_ID,
                region=DEFAULT_REGION,
                event_type=event_type,
                user=user,
                source_ip=source_ip,
                resource_type=template.resource_type,
                resource_id=resource_id or self._resource_id(template, user),
                action=template.action,
                severity=template.severity,
                details={**template.details, **(details or {})},
            )
        except ValueError as exc:  # pydantic.ValidationError subclasses ValueError
            raise InvalidEventError(str(exc)) from exc
        event = event.model_copy(update={"raw_event": _raw_event(event, template)})
        logger.debug("event generated: %s %s by %s", event.event_type, event.event_id, user)
        return event

    def normal_event(
        self, user: str | None = None, timestamp: datetime | None = None
    ) -> SecurityEvent:
        """A routine event from a user's usual IP."""
        user = user or self._rng.choice(list(KNOWN_USER_IPS))
        event_type = self._rng.choice(NORMAL_EVENT_TYPES)
        details = {"key": self._rng.choice(SAMPLE_OBJECT_KEYS)} if event_type == "GetObject" else None
        return self.create_event(event_type, user=user, source_ip=KNOWN_USER_IPS[user],
                                 timestamp=timestamp, details=details)

    def normal_batch(self, count: int, window_minutes: int = 30) -> list[SecurityEvent]:
        """`count` normal events spread over the last `window_minutes`, oldest first."""
        now = self._clock()
        stamps = sorted(now - timedelta(seconds=self._rng.uniform(0, window_minutes * 60))
                        for _ in range(count))
        return [self.normal_event(timestamp=ts) for ts in stamps]

    def suspicious_event(
        self, user: str | None = None, timestamp: datetime | None = None
    ) -> SecurityEvent:
        """A suspicious event from an unusual IP."""
        user = user or self._rng.choice(list(KNOWN_USER_IPS))
        event_type = self._rng.choice(SUSPICIOUS_EVENT_TYPES)
        details = {"anomaly": "unusual_source_ip"} if event_type == "Login" else None
        return self.create_event(event_type, user=user, source_ip=self.suspicious_ip(),
                                 timestamp=timestamp, details=details)

    def suspicious_ip(self) -> str:
        """Pick an unusual (attacker) IP."""
        return self._rng.choice(SUSPICIOUS_IPS)

    def _resource_id(self, template: EventTemplate, user: str) -> str:
        if template.resource_id:
            return template.resource_id
        if template.resource_type == "S3Bucket":
            return self._rng.choice(BUCKETS)
        if template.resource_type == "EC2Instance":
            return self._rng.choice(INSTANCES)
        return user


def _raw_event(event: SecurityEvent, template: EventTemplate) -> dict[str, Any]:
    """The record as the source service would have logged it (CloudTrail or flow-log shape)."""
    params = {k: v for k, v in event.details.items() if k not in GROUND_TRUTH_KEYS}
    if event.source == EventSource.VPC_FLOW_LOGS:
        return {
            "version": 2,
            "account-id": event.account_id,
            "resource-id": event.resource_id,
            "srcaddr": event.source_ip,
            "dstaddr": params.get("destination_ip"),
            "dstport": params.get("destination_port"),
            "bytes": params.get("bytes_out"),
            "direction": params.get("direction"),
            "action": "ACCEPT",
            "start": event.timestamp.isoformat(),
            "log-status": "OK",
        }
    return {
        "eventVersion": "1.09",
        "eventID": event.event_id,
        "eventTime": event.timestamp.isoformat(),
        "eventSource": template.service,
        "eventName": event.event_type,
        "awsRegion": event.region,
        "sourceIPAddress": event.source_ip,
        "recipientAccountId": event.account_id,
        "userIdentity": {"type": "IAMUser", "userName": event.user,
                         "accountId": event.account_id},
        "resources": [{"type": event.resource_type, "id": event.resource_id}],
        "requestParameters": params,
    }
