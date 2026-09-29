"""The security event model shared by the simulator, the database layer, tools and agents."""

import ipaddress
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field, field_validator

from app.domain.enums import EventSource, Severity

# The simulated AWS account every event belongs to (documentation-style ID, not real).
SIMULATED_ACCOUNT_ID = "123456789012"
DEFAULT_REGION = "us-east-1"


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


class SecurityEvent(BaseModel):
    """One cloud security/audit event (simulated in this phase).

    `user` is the acting principal; it is also exposed as `principal_id`.
    `severity` is the hint supplied by the event source (e.g. a GuardDuty finding
    severity or a detection-rule default) - it is NOT a triage decision.
    """

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utcnow)
    source: EventSource = EventSource.CLOUDTRAIL
    account_id: str = SIMULATED_ACCOUNT_ID
    region: str = DEFAULT_REGION
    event_type: str = Field(min_length=1)
    user: str = Field(min_length=1)
    source_ip: str
    resource_type: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    severity: Severity = Severity.INFO
    details: dict[str, Any] = Field(default_factory=dict)
    raw_event: dict[str, Any] = Field(default_factory=dict)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def principal_id(self) -> str:
        """The identity that performed the action (same value as `user`)."""
        return self.user

    @field_validator("source_ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError(f"'{value}' is not a valid IP address") from None
        return value

    @field_validator("timestamp")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
