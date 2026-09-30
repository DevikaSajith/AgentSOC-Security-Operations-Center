"""Stage 7: should this event group become an incident? (deterministic, config-driven)

IMPORTANT - what these numbers mean:
  * severity / priority are the Monitor's INITIAL signal only. The Triage Agent (a later
    phase) performs the actual security prioritization and may change both.
  * confidence is confidence that the group SHOULD BE TREATED AS AN INCIDENT. It says
    nothing about what the attacker is doing (that is the Investigator's job).
"""

from app.agents.monitor.config import MonitorConfig
from app.agents.monitor.enrichment import SEVERITY_RANK
from app.agents.monitor.models import EnrichedEvent, EventGroup, IncidentDecision
from app.domain.enums import IncidentCategory

# Group-level indicators that do not count as independent evidence for the
# "correlated group" rule (the group's size is what that rule already measures).
# ml_threat_predicted is a supporting signal only: it can raise confidence but never counts as independent
# evidence and never triggers incident creation by itself.
_NOT_INDEPENDENT = {"correlated_group", "ml_threat_predicted"}


def primary_event(group: EventGroup) -> EnrichedEvent:
    """The most significant event: highest severity, then most indicators, then latest."""
    return max(group.events, key=lambda e: (SEVERITY_RANK[e.event.severity], len(e.indicators),
                                            e.event.timestamp, e.event.event_id))


def category_for(group: EventGroup, config: MonitorConfig) -> IncidentCategory:
    """Group signals first, then the primary event's type, then its resource type."""
    if "principal_ip_change" in group.group_indicators:
        return IncidentCategory.CREDENTIAL  # a valid identity used from a new, untrusted place
    # Weighted vote: significant events decide the category of the group.
    votes: dict[IncidentCategory, int] = {}
    for item in group.events:
        event = item.event
        category = (config.category_by_event_type.get(event.event_type)
                    or config.category_by_resource_type.get(event.resource_type)
                    or IncidentCategory.OTHER)
        votes[category] = votes.get(category, 0) + 1 + SEVERITY_RANK[event.severity] + len(item.indicators)
    best = max(votes.values())
    primary = primary_event(group).event
    fallback = (config.category_by_event_type.get(primary.event_type)
                or config.category_by_resource_type.get(primary.resource_type)
                or IncidentCategory.OTHER)
    tied = [c for c, v in votes.items() if v == best]
    return fallback if fallback in tied else sorted(tied, key=lambda c: c.value)[0]


def confidence_for(indicators: list[str], config: MonitorConfig) -> float:
    """Noisy-OR of the configured weights of the distinct indicators present."""
    miss = 1.0
    for indicator in set(indicators):
        miss *= 1.0 - config.confidence.indicator_weights.get(indicator, 0.0)
    return round(min(1.0 - miss, config.confidence.max_confidence), 3)


def decide(group: EventGroup, config: MonitorConfig) -> IncidentDecision:
    rules = config.incident.create_when
    indicators = group.indicators()
    matched = []
    if any("high_severity" in e.indicators for e in group.events):
        matched.append(f"event_severity_at_least_{rules.min_event_severity.value}")
    if rules.any_suspicious_event_type and any(
            "suspicious_event_type" in e.indicators for e in group.events):
        matched.append("suspicious_event_type")
    independent = [i for i in indicators if i not in _NOT_INDEPENDENT]
    if (len(group.events) >= rules.correlated_group.min_events
            and len(independent) >= rules.correlated_group.min_distinct_indicators):
        matched.append("correlated_suspicious_group")

    create = bool(matched)
    primary = primary_event(group)
    severity = max((e.event.severity for e in group.events), key=SEVERITY_RANK.__getitem__)
    floor = config.incident.severity_floor
    if create and SEVERITY_RANK[severity] < SEVERITY_RANK[floor]:
        severity = floor
    confidence = confidence_for(indicators, config) if create else 0.0
    if create:
        reason = (f"{len(group.events)} event(s) by {group.principal_id} matched "
                  f"{', '.join(matched)}; indicators: {', '.join(indicators)}")
    elif independent:
        reason = f"below incident threshold; indicators: {', '.join(indicators)}"
    else:
        reason = "no security indicators; routine activity"
    return IncidentDecision(
        create_incident=create, rules_matched=matched, indicators=indicators,
        confidence=confidence, severity=severity,
        priority=config.priority_by_severity[severity],
        category=category_for(group, config), primary_event_id=primary.event.event_id,
        reason=reason)
