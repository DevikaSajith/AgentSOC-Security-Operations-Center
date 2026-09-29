"""Deterministic timeline reconstruction (the model never supplies timestamps)."""

from app.agents.investigator.evidence import EvidenceCatalog
from app.domain.investigation import TimelineEntry

UNSPECIFIED_IP = "0.0.0.0"


def build_timeline(catalog: EvidenceCatalog) -> list[TimelineEntry]:
    """Chronological entries for the incident's events (undated ones last), each traceable
    to an EV id, with the gap to the previous event and what it shares with it."""
    entries: list[TimelineEntry] = []
    previous = None
    for event in catalog.events:
        shared = []
        gap = None
        if previous is not None:
            if event.principal == previous.principal and event.principal != "unknown":
                shared.append("same_principal")
            if event.source_ip == previous.source_ip and event.source_ip != UNSPECIFIED_IP:
                shared.append("same_source_ip")
            if (event.resource_type, event.resource_id) == (previous.resource_type, previous.resource_id) \
                    and event.resource_id != "*":
                shared.append("same_resource")
            if event.account_id == previous.account_id:
                shared.append("same_account")
            if event.timestamp and previous.timestamp:
                gap = round((event.timestamp - previous.timestamp).total_seconds(), 1)
        entries.append(TimelineEntry(
            evidence_id=event.evidence_id, timestamp=event.timestamp, event_type=event.event_type,
            source=event.source, principal=event.principal, source_ip=event.source_ip,
            resource=f"{event.resource_type}/{event.resource_id}", seconds_since_previous=gap,
            shared_with_previous=shared))
        previous = event
    return entries
