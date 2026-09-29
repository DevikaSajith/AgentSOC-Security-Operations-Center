"""Stage 1+2: validate incoming events and normalize them into the common SecurityEvent.

Supported input shapes (all SIMULATED/local in this project; nothing is read from AWS):
  - SecurityEvent dicts (the simulator/event-store shape; source may be any EventSource,
    including the service-native IAM / EC2 / S3 values)
  - CloudTrail records          (eventName, eventTime, eventSource, ...)
  - VPC Flow Log records        (srcaddr, dstaddr, dstport, start, ...)
  - GuardDuty findings          (type, severity 0-10, resource, service, ...)
  - Security Hub ASFF findings  (SchemaVersion, Types, Severity.Label, Resources, ...)

Every failure becomes an EventRejection (never an exception escaping the agent).
"""

import hashlib
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from pydantic import ValidationError

from app.agents.monitor.config import MonitorConfig
from app.agents.monitor.fingerprint import canonical_json, fingerprint
from app.agents.monitor.models import (
    UNKNOWN_PRINCIPAL,
    UNSPECIFIED_IP,
    IngestFormat,
    NormalizedEvent,
    RejectedEvent,
)
from app.domain.enums import EventSource, Severity
from app.domain.events import DEFAULT_REGION, SIMULATED_ACCOUNT_ID, SecurityEvent, utcnow

SEVERITY_ALIASES = {"informational": Severity.INFO, "information": Severity.INFO}


class EventRejection(Exception):
    """Raised inside the normalizer; converted into a RejectedEvent by the caller."""

    def __init__(self, reason: str, detail: str = "", event_id: str | None = None) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail, self.event_id = reason, detail, event_id


# ------------------------------------------------------------------------ helpers
def _get(data: Any, *path: str | int) -> Any:
    """Safe nested lookup: None if any level is missing or of the wrong type."""
    for key in path:
        if isinstance(key, int):
            if not isinstance(data, list) or len(data) <= key:
                return None
            data = data[key]
        elif isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _ip_or_unspecified(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip())) if value else UNSPECIFIED_IP
    except ValueError:
        return UNSPECIFIED_IP  # e.g. "ec2.amazonaws.com" for AWS-service callers


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", re.sub(r"[^A-Za-z0-9]", "", name)).lower() or "event"


def parse_timestamp(value: Any) -> datetime:
    """ISO-8601 string, epoch seconds or datetime -> aware UTC datetime."""
    if value is None or value == "":
        raise EventRejection("missing_timestamp")
    try:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
        elif isinstance(value, str):
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        else:
            raise ValueError
    except (ValueError, OverflowError, OSError):
        raise EventRejection("invalid_timestamp", "not ISO-8601 or epoch seconds") from None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def parse_severity(value: Any, event_type: str, config: MonitorConfig) -> Severity:
    """Keep a supplied severity (validated); derive one from config only if absent."""
    if value is None or value == "":
        return config.default_severity_by_event_type.get(event_type, Severity.INFO)
    if isinstance(value, str):
        key = value.strip().lower()
        if key in SEVERITY_ALIASES:
            return SEVERITY_ALIASES[key]
        try:
            return Severity(key)
        except ValueError:
            pass
    raise EventRejection("invalid_severity", "severity must be critical/high/medium/low/info")


def _guardduty_severity(value: Any) -> Severity:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 10:
        raise EventRejection("invalid_severity", "GuardDuty severity must be a number 0-10")
    if value >= 9:
        return Severity.CRITICAL
    if value >= 7:
        return Severity.HIGH
    if value >= 4:
        return Severity.MEDIUM
    return Severity.LOW if value >= 1 else Severity.INFO


MAX_EVENT_ID = 36  # width of events.event_id


def _required_text(value: Any, field: str, max_length: int = 200) -> str:
    text = _text(value)
    if text is None:
        raise EventRejection("missing_identifier", f"'{field}' is required")
    if len(text) > max_length:
        raise EventRejection("invalid_identifier", f"'{field}' longer than {max_length} characters")
    return text


def _event_id(value: Any, field: str) -> str:
    """The source's record ID; long ones (e.g. Security Hub ARNs) get a stable short form."""
    text = _required_text(value, field, max_length=1024)
    if len(text) <= MAX_EVENT_ID:
        return text
    return "id-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:MAX_EVENT_ID - 3]


# ------------------------------------------------------------------ format parsers
def detect_format(data: dict[str, Any]) -> IngestFormat:
    if "eventName" in data:
        return "cloudtrail"
    if "SchemaVersion" in data and ("Types" in data or "Severity" in data):
        return "security_hub"
    if "type" in data and "service" in data and "severity" in data:
        return "guardduty"
    if "srcaddr" in data or "dstaddr" in data:
        return "vpc_flow_log"
    if "event_type" in data:
        return "security_event"
    raise EventRejection("unrecognized_format",
                         "not a SecurityEvent, CloudTrail, VPC flow, GuardDuty or ASFF record")


def _from_security_event(data: dict[str, Any], config: MonitorConfig) -> dict[str, Any]:
    source = data.get("source")
    if source is None:
        raise EventRejection("missing_field", "'source' is required")
    try:
        EventSource(source)
    except ValueError:
        raise EventRejection("unsupported_source",
                             f"supported: {', '.join(s.value for s in EventSource)}") from None
    event_type = _text(data.get("event_type")) or ""
    return {
        **data,
        "event_id": _event_id(data.get("event_id"), "event_id"),
        "user": _text(data.get("user")) or _text(data.get("principal_id")) or UNKNOWN_PRINCIPAL,
        "timestamp": parse_timestamp(data.get("timestamp")),
        "severity": parse_severity(data.get("severity"), event_type, config),
    }


# CloudTrail eventSource -> (requestParameters keys, resource type), in priority order.
_CLOUDTRAIL_RESOURCES: dict[str, list[tuple[str, str]]] = {
    "iam.amazonaws.com": [("userName", "IAMUser"), ("roleName", "IAMRole")],
    "s3.amazonaws.com": [("bucketName", "S3Bucket")],
    "ec2.amazonaws.com": [("instanceId", "EC2Instance"), ("groupId", "SecurityGroup")],
    "ssm.amazonaws.com": [("instanceId", "EC2Instance")],
    "secretsmanager.amazonaws.com": [("secretId", "Secret")],
}


def _cloudtrail_resource(data: dict[str, Any], principal: str) -> tuple[str, str]:
    params = data.get("requestParameters") or {}
    for key, resource_type in _CLOUDTRAIL_RESOURCES.get(str(data.get("eventSource")), []):
        value = _text(params.get(key)) or _text(_get(params, "instancesSet", "items", 0, key))
        if value:
            return resource_type, value
    listed = _get(data, "resources", 0)
    if isinstance(listed, dict) and _text(listed.get("id")):
        return _text(listed.get("type")) or "Resource", listed["id"]
    return "IAMUser", principal  # e.g. ConsoleLogin: the resource is the identity itself


def _from_cloudtrail(data: dict[str, Any], config: MonitorConfig) -> dict[str, Any]:
    identity = data.get("userIdentity") or {}
    principal = (_text(identity.get("userName")) or _text(str(identity.get("arn", "")).split("/")[-1])
                 or _text(identity.get("principalId")) or UNKNOWN_PRINCIPAL)
    event_type = _required_text(data.get("eventName"), "eventName", 100)
    resource_type, resource_id = _cloudtrail_resource(data, principal)
    return {
        "event_id": _event_id(data.get("eventID"), "eventID"),
        "timestamp": parse_timestamp(data.get("eventTime")),
        "source": EventSource.CLOUDTRAIL,
        "account_id": _text(data.get("recipientAccountId")) or _text(identity.get("accountId"))
        or SIMULATED_ACCOUNT_ID,
        "region": _text(data.get("awsRegion")) or DEFAULT_REGION,
        "event_type": event_type,
        "user": principal,
        "source_ip": _ip_or_unspecified(data.get("sourceIPAddress")),
        "resource_type": resource_type,
        "resource_id": resource_id,
        "action": _snake(event_type),
        "severity": parse_severity(None, event_type, config),
        "details": {"event_source": data.get("eventSource"),
                    "request_parameters": data.get("requestParameters") or {}},
    }


def _from_vpc_flow(data: dict[str, Any], config: MonitorConfig) -> dict[str, Any]:
    resource_id = (_text(data.get("resource-id")) or _text(data.get("instance-id"))
                   or _text(data.get("interface-id")))
    if resource_id is None:
        raise EventRejection("missing_identifier", "a resource-id or interface-id is required")
    flagged = str(data.get("action", "")).upper() == "REJECT"
    event_type = "NetworkFlowRejected" if flagged else "NetworkFlow"
    digest = hashlib.sha256(canonical_json(data).encode()).hexdigest()[:24]
    return {
        "event_id": f"flow-{digest}",  # flow logs carry no record ID; derived deterministically
        "timestamp": parse_timestamp(data.get("start")),
        "source": EventSource.VPC_FLOW_LOGS,
        "account_id": _text(str(data.get("account-id") or "")) or SIMULATED_ACCOUNT_ID,
        "region": _text(data.get("region")) or DEFAULT_REGION,
        "event_type": event_type,
        "user": UNKNOWN_PRINCIPAL,
        "source_ip": _ip_or_unspecified(data.get("srcaddr")),
        "resource_type": "EC2Instance" if resource_id.startswith(("i-", "ec2-")) else "NetworkInterface",
        "resource_id": resource_id,
        "action": _snake(event_type),
        "severity": parse_severity(None, event_type, config),
        "details": {k: data.get(k) for k in ("dstaddr", "dstport", "bytes", "direction", "action")
                    if data.get(k) is not None},
    }


def _from_guardduty(data: dict[str, Any], _: MonitorConfig) -> dict[str, Any]:
    resource = data.get("resource") or {}
    kind = resource.get("resourceType")
    principal = _text(_get(resource, "accessKeyDetails", "userName")) or UNKNOWN_PRINCIPAL
    if kind == "Instance":
        resource_type, resource_id = "EC2Instance", _get(resource, "instanceDetails", "instanceId")
    elif kind == "S3Bucket":
        resource_type, resource_id = "S3Bucket", _get(resource, "s3BucketDetails", 0, "name")
    else:
        resource_type, resource_id = "IAMUser", principal
    action = _get(data, "service", "action") or {}
    ip = (_get(action, "awsApiCallAction", "remoteIpDetails", "ipAddressV4")
          or _get(action, "networkConnectionAction", "remoteIpDetails", "ipAddressV4"))
    event_type = _required_text(data.get("type"), "type", 100)
    return {
        "event_id": _event_id(data.get("id"), "id"),
        "timestamp": parse_timestamp(data.get("updatedAt") or data.get("createdAt")),
        "source": EventSource.GUARDDUTY,
        "account_id": _text(data.get("accountId")) or SIMULATED_ACCOUNT_ID,
        "region": _text(data.get("region")) or DEFAULT_REGION,
        "event_type": event_type,
        "user": principal,
        "source_ip": _ip_or_unspecified(ip),
        "resource_type": resource_type,
        "resource_id": _text(resource_id) or principal,
        "action": _snake(event_type.split("/")[-1]),
        "severity": _guardduty_severity(data.get("severity")),
        "details": {"title": data.get("title")},
    }


_ASFF_RESOURCE_TYPES = {"AwsS3Bucket": "S3Bucket", "AwsEc2Instance": "EC2Instance",
                        "AwsIamUser": "IAMUser", "AwsEc2SecurityGroup": "SecurityGroup"}


def _from_security_hub(data: dict[str, Any], config: MonitorConfig) -> dict[str, Any]:
    resource = _get(data, "Resources", 0) or {}
    arn = _text(resource.get("Id")) or ""
    resource_type = _ASFF_RESOURCE_TYPES.get(resource.get("Type"), "Resource")
    resource_id = re.split(r"[:/]", arn)[-1] if arn else None
    principal = resource_id if resource_type == "IAMUser" and resource_id else UNKNOWN_PRINCIPAL
    event_type = _text(data.get("Title")) or _text(_get(data, "Types", 0))
    if not event_type:
        raise EventRejection("missing_field", "'Title' or 'Types' is required")
    return {
        "event_id": _event_id(data.get("Id"), "Id"),
        "timestamp": parse_timestamp(data.get("UpdatedAt") or data.get("CreatedAt")),
        "source": EventSource.SECURITY_HUB,
        "account_id": _text(data.get("AwsAccountId")) or SIMULATED_ACCOUNT_ID,
        "region": _text(data.get("Region")) or DEFAULT_REGION,
        "event_type": event_type[:100],
        "user": principal,
        "source_ip": _ip_or_unspecified(_get(data, "Network", "SourceIpV4")),
        "resource_type": resource_type,
        "resource_id": resource_id or principal,
        "action": "security_hub_finding",
        "severity": parse_severity(_get(data, "Severity", "Label"), event_type, config),
        "details": {"types": data.get("Types") or [], "generator_id": data.get("GeneratorId")},
    }


_PARSERS: dict[str, Callable[[dict[str, Any], MonitorConfig], dict[str, Any]]] = {
    "security_event": _from_security_event,
    "cloudtrail": _from_cloudtrail,
    "vpc_flow_log": _from_vpc_flow,
    "guardduty": _from_guardduty,
    "security_hub": _from_security_hub,
}


# ------------------------------------------------------------------ public API
class EventNormalizer:
    """Validates and normalizes events. `clock` is injectable for tests."""

    def __init__(self, config: MonitorConfig, clock: Callable[[], datetime] = utcnow) -> None:
        self._config = config
        self._clock = clock

    def normalize_raw(self, data: Any) -> NormalizedEvent:
        """A submitted raw event (any supported shape). Raises EventRejection."""
        if not isinstance(data, dict):
            raise EventRejection("schema_invalid", "event must be a JSON object")
        ingest_format = detect_format(data)
        fields = _PARSERS[ingest_format](data, self._config)
        if ingest_format != "security_event":
            fields["raw_event"] = data  # keep the record exactly as received
        fields["details"] = {**(fields.get("details") or {}),
                             "ingest": {"format": ingest_format, "origin": "submitted"}}
        try:
            event = SecurityEvent.model_validate(fields)
        except ValidationError as exc:
            problems = ", ".join(sorted({".".join(map(str, e["loc"])) for e in exc.errors()}))
            raise EventRejection("schema_invalid", f"invalid fields: {problems}",
                                 fields.get("event_id")) from None
        return self._checked(event, ingest_format, stored=False)

    def normalize_stored(self, event: SecurityEvent) -> NormalizedEvent:
        """An event already in the event store (simulator output). Raises EventRejection."""
        return self._checked(event, "security_event", stored=True)

    def _checked(self, event: SecurityEvent, ingest_format: IngestFormat,
                 stored: bool) -> NormalizedEvent:
        if event.principal_id == UNKNOWN_PRINCIPAL and event.resource_id in ("", "*"):
            raise EventRejection("missing_identifier",
                                 "an event needs a principal or a specific resource",
                                 event.event_id)
        now = self._clock()
        rules = self._config.validation
        if event.timestamp > now + timedelta(seconds=rules.max_future_skew_seconds):
            raise EventRejection("invalid_timestamp", "timestamp is in the future", event.event_id)
        if event.timestamp < now - timedelta(days=rules.max_event_age_days):
            raise EventRejection("stale_event", f"older than {rules.max_event_age_days} days",
                                 event.event_id)
        return NormalizedEvent(event=event, fingerprint=fingerprint(event),
                               ingest_format=ingest_format, stored=stored)


def rejection_record(exc: EventRejection, index: int | None = None) -> RejectedEvent:
    return RejectedEvent(index=index, event_id=exc.event_id, reason=exc.reason, detail=exc.detail)
