"""Stage 8: build a new IncidentState from an event group, or merge a group into an
existing open incident. Only Monitor-owned fields are filled; investigation, compliance,
remediation and verification stay empty/pending for the later agents."""

from datetime import datetime, timedelta
from typing import Any

from app.agents.monitor.config import MonitorConfig
from app.agents.monitor.enrichment import SEVERITY_RANK
from app.agents.monitor.models import UNKNOWN_PRINCIPAL, UNSPECIFIED_IP, EventGroup, IncidentDecision
from app.domain.enums import AgentName, IncidentStatus
from app.domain.incident import AffectedResource, AgentDecision, Evidence, IncidentState

CATEGORY_LABELS = {"iam": "IAM", "s3": "S3", "ec2": "EC2", "network": "Network",
                   "credential": "Credential", "other": "Suspicious"}


def _affected(group: EventGroup) -> list[AffectedResource]:
    seen: dict[tuple[str, str], AffectedResource] = {}
    principal = group.principal_id
    if principal != UNKNOWN_PRINCIPAL:
        seen[("IAMUser", principal)] = AffectedResource(resource_type="IAMUser", resource_id=principal)
    for item in group.events:
        event = item.event
        if event.resource_id != "*":
            seen.setdefault((event.resource_type, event.resource_id), AffectedResource(
                resource_type=event.resource_type, resource_id=event.resource_id))
    return list(seen.values())


def evidence_for(group: EventGroup, now: datetime) -> list[Evidence]:
    evidence = []
    for item in group.events:
        event = item.event
        evidence.append(Evidence(
            kind="event", event_id=event.event_id, collected_by=AgentName.MONITOR, collected_at=now,
            description=(f"{event.event_type} by {event.principal_id} from {event.source_ip} "
                         f"on {event.resource_type}/{event.resource_id}"),
            data={"timestamp": event.timestamp.isoformat(), "source": event.source.value,
                  "event_type": event.event_type, "principal_id": event.principal_id,
                  "source_ip": event.source_ip, "resource_type": event.resource_type,
                  "resource_id": event.resource_id, "severity": event.severity.value,
                  "indicators": item.indicators, "fingerprint": item.normalized.fingerprint}))
    for resource, state in group.resource_context.items():
        evidence.append(Evidence(
            kind="cloud_state", collected_by=AgentName.MONITOR, collected_at=now,
            description=f"Simulated cloud state of {resource} when the Monitor ran",
            data={"resource": resource, "state": state, "simulated": True}))
    return evidence


def build_incident(group: EventGroup, decision: IncidentDecision, now: datetime) -> IncidentState:
    primary = next(e for e in group.events if e.event.event_id == decision.primary_event_id)
    event = primary.event
    first, last = group.events[0].event.timestamp, group.events[-1].event.timestamp
    count = len(group.events)
    title = f"{CATEGORY_LABELS[decision.category.value]} activity by {event.principal_id}: {event.event_type}"
    if count > 1:
        title += f" (+{count - 1} correlated event{'s' if count > 2 else ''})"
    normalized = event.model_dump(mode="json", exclude={"raw_event"})
    normalized.update({"fingerprint": primary.normalized.fingerprint,
                       "ingest_format": primary.normalized.ingest_format,
                       "indicators": primary.indicators, "group_indicators": decision.indicators,
                       "rules_matched": decision.rules_matched, "simulated": True})
    return IncidentState(
        timestamp=now, updated_at=now, title=title[:255],
        description=(f"Opened by the Monitor Agent from {count} correlated event(s) between "
                     f"{first.isoformat()} and {last.isoformat()}. {decision.reason}. "
                     "Severity and priority are initial signals pending triage."),
        source=event.source, event_type=event.event_type, account_id=event.account_id,
        region=event.region, resource_id=event.resource_id, principal_id=event.principal_id,
        source_ip=None if event.source_ip == UNSPECIFIED_IP else event.source_ip,
        raw_event=event.raw_event, normalized_event=normalized,
        related_event_ids=group.event_ids,
        severity=decision.severity, priority=decision.priority, category=decision.category,
        confidence=decision.confidence,
        affected_resources=_affected(group), evidence=evidence_for(group, now),
        current_agent=AgentName.MONITOR, final_status=IncidentStatus.NEW,
        agent_decisions=[AgentDecision(actor=AgentName.MONITOR, decision="create_incident",
                                       reasoning=decision.reason, confidence=decision.confidence,
                                       timestamp=now)],
    )


def _incident_ips(incident: IncidentState) -> set[str]:
    ips = {e.data.get("source_ip") for e in incident.evidence if e.kind == "event"}
    return {ip for ip in ips if ip and ip != UNSPECIFIED_IP}


def matches_open_incident(incident: IncidentState, group: EventGroup, decision: IncidentDecision,
                          config: MonitorConfig, now: datetime) -> bool:
    """Conservative merge rule (see config/monitor_rules.yaml: incident.merge_window_minutes)."""
    if incident.final_status.value in config.incident.closed_statuses:
        return False
    if incident.principal_id != group.principal_id or group.principal_id == UNKNOWN_PRINCIPAL:
        return False
    if incident.category != decision.category:
        return False
    if now - incident.updated_at > timedelta(minutes=config.incident.merge_window_minutes):
        return False
    group_ips = {e.event.source_ip for e in group.events} - {UNSPECIFIED_IP}
    own = ("IAMUser", group.principal_id)  # every Login touches it; not a meaningful overlap
    resources = {(r.resource_type, r.resource_id) for r in incident.affected_resources} - {own}
    group_resources = {(r.resource_type, r.resource_id) for r in _affected(group)} - {own}
    return bool(group_ips & _incident_ips(incident)) or bool(resources & group_resources)


def merge_into(incident: IncidentState, group: EventGroup, decision: IncidentDecision,
               config: MonitorConfig, now: datetime) -> IncidentState:
    new_ids = [i for i in group.event_ids if i not in incident.related_event_ids]
    known_resources = {(r.resource_type, r.resource_id) for r in incident.affected_resources}
    severity = max(incident.severity, decision.severity, key=SEVERITY_RANK.__getitem__)
    update: dict[str, Any] = {
        "related_event_ids": incident.related_event_ids + new_ids,
        "evidence": incident.evidence + [e for e in evidence_for(group, now)
                                         if e.kind != "event" or e.event_id in new_ids],
        "affected_resources": incident.affected_resources + [
            r for r in _affected(group) if (r.resource_type, r.resource_id) not in known_resources],
        "severity": severity,
        "priority": config.priority_by_severity[severity],
        "confidence": max(incident.confidence, decision.confidence),
        "agent_decisions": incident.agent_decisions + [AgentDecision(
            actor=AgentName.MONITOR, decision="update_incident", confidence=decision.confidence,
            reasoning=f"{len(new_ids)} new correlated event(s) added. {decision.reason}",
            timestamp=now)],
    }
    return incident.model_copy(update=update)
