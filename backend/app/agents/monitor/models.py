"""Data passed between the Monitor Agent's pipeline stages, plus its API contract."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.agent_result import AgentResult
from app.domain.enums import IncidentCategory, Priority, Severity
from app.domain.events import SecurityEvent

IngestFormat = Literal["security_event", "cloudtrail", "vpc_flow_log", "guardduty",
                       "security_hub"]

# Placeholders for fields some sources do not carry. Never used as correlation keys.
UNKNOWN_PRINCIPAL = "unknown"
UNSPECIFIED_IP = "0.0.0.0"


class NormalizedEvent(BaseModel):
    """A validated event in the common SecurityEvent shape plus ingest metadata."""

    event: SecurityEvent
    fingerprint: str
    ingest_format: IngestFormat
    stored: bool  # already persisted in the event store before this run


class RejectedEvent(BaseModel):
    """An input that failed validation. Holds no raw payload (it may be sensitive)."""

    index: int | None = None  # position in the submitted `events` list
    event_id: str | None = None
    reason: str
    detail: str = ""


class DuplicateEvent(BaseModel):
    event_id: str
    duplicate_of: str
    kind: Literal["in_batch", "previously_processed"]


class EnrichedEvent(BaseModel):
    """A normalized event plus deterministic context."""

    normalized: NormalizedEvent
    indicators: list[str] = Field(default_factory=list)
    source_ip_trusted: bool | None = None  # None: no usable IP

    @property
    def event(self) -> SecurityEvent:
        return self.normalized.event


class EventGroup(BaseModel):
    """Events linked by correlation (same principal + same IP or resource, within window)."""

    group_id: str
    events: list[EnrichedEvent]
    resource_context: dict[str, dict[str, Any]] = Field(default_factory=dict)
    group_indicators: list[str] = Field(default_factory=list)

    @property
    def event_ids(self) -> list[str]:
        return [e.event.event_id for e in self.events]

    @property
    def principal_id(self) -> str:
        return self.events[0].event.principal_id

    def indicators(self) -> list[str]:
        """Distinct indicators across events and the group itself, in stable order."""
        seen: dict[str, None] = {}
        for item in [i for e in self.events for i in e.indicators] + self.group_indicators:
            seen.setdefault(item, None)
        return list(seen)


class IncidentDecision(BaseModel):
    """Whether a group becomes an incident, and the Monitor's INITIAL classification."""

    create_incident: bool
    rules_matched: list[str]
    indicators: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    priority: Priority
    category: IncidentCategory
    primary_event_id: str
    reason: str


class GroupReport(BaseModel):
    group_id: str
    event_ids: list[str]
    principal_id: str
    source_ips: list[str]
    indicators: list[str]
    decision: Literal["incident_created", "incident_updated", "no_incident"]
    rules_matched: list[str]
    incident_id: str | None = None
    confidence: float


# ------------------------------------------------------------------------ API
class MonitorRunRequest(BaseModel):
    """What to process. With no selector, all not-yet-processed stored events are used."""

    model_config = ConfigDict(extra="forbid")

    event_ids: list[str] | None = Field(default=None, max_length=1000)
    # list[Any], not list[dict]: a malformed item is rejected individually (and audited)
    # instead of failing the whole batch with a 422.
    events: list[Any] | None = Field(
        default=None, max_length=500,
        description="Raw events to ingest (SecurityEvent, CloudTrail, VPC flow log, "
                    "GuardDuty or Security Hub shape). Accepted ones are stored.")
    time_window_minutes: int | None = Field(
        default=None, ge=1, le=10080,
        description="Only consider stored events newer than this (default: no limit).")
    limit: int = Field(default=500, ge=1, le=1000)

    @model_validator(mode="after")
    def _one_selector(self) -> "MonitorRunRequest":
        if self.event_ids is not None and self.events is not None:
            raise ValueError("give either event_ids or events, not both")
        if self.event_ids and any(not i or len(i) > 64 for i in self.event_ids):
            raise ValueError("event_ids must be non-empty strings of at most 64 characters")
        return self


class MonitorRunReport(BaseModel):
    run_id: str
    processed_events: int
    accepted_event_ids: list[str]
    rejected_events: list[RejectedEvent]
    duplicates: list[DuplicateEvent]
    already_processed: list[str]
    correlated_groups: list[GroupReport]
    incidents_created: list[str]
    incidents_updated: list[str]
    agent_result: AgentResult
    incident_results: list[AgentResult]
