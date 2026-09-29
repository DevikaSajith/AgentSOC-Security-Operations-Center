"""Stage 6: deterministic enrichment.

Per event:  high_severity, suspicious_event_type, untrusted_source_ip, sensitive_resource
Per group:  correlated_group, principal_ip_change (same principal seen from trusted AND
            untrusted IPs), privileged_principal (current simulated cloud state)
Cloud state comes from a lookup callable (the agent wires it to the read-only
`get_resource` tool), results are cached per resource for the run.
"""

import ipaddress
from typing import Any, Callable

from app.agents.monitor.config import MonitorConfig
from app.agents.monitor.correlation import group_id
from app.agents.monitor.models import UNKNOWN_PRINCIPAL, UNSPECIFIED_IP, EnrichedEvent, EventGroup, NormalizedEvent
from app.domain.enums import Severity

SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3,
                 Severity.CRITICAL: 4}
LOOKUP_RESOURCE_TYPES = ("IAMUser", "EC2Instance", "S3Bucket")

ResourceLookup = Callable[[str, str], dict[str, Any] | None]


class Enricher:
    def __init__(self, config: MonitorConfig, resource_lookup: ResourceLookup | None = None) -> None:
        self._config = config
        self._networks = config.networks()
        self._lookup = resource_lookup
        self._cache: dict[tuple[str, str], dict[str, Any] | None] = {}

    def is_trusted_ip(self, ip: str) -> bool | None:
        if ip == UNSPECIFIED_IP:
            return None
        address = ipaddress.ip_address(ip)
        return any(address in network for network in self._networks)

    def enrich_event(self, item: NormalizedEvent) -> EnrichedEvent:
        event, config = item.event, self._config
        indicators = []
        if SEVERITY_RANK[event.severity] >= SEVERITY_RANK[config.incident.create_when.min_event_severity]:
            indicators.append("high_severity")
        if event.event_type in config.suspicious_event_types:
            indicators.append("suspicious_event_type")
        trusted = self.is_trusted_ip(event.source_ip)
        if trusted is False:
            indicators.append("untrusted_source_ip")
        if event.resource_id in config.sensitive_resources:
            indicators.append("sensitive_resource")
        return EnrichedEvent(normalized=item, indicators=indicators, source_ip_trusted=trusted)

    def build_group(self, items: list[NormalizedEvent]) -> EventGroup:
        events = [self.enrich_event(i) for i in items]
        group_indicators = []
        if len(events) >= self._config.incident.create_when.correlated_group.min_events:
            group_indicators.append("correlated_group")
        trust = {e.source_ip_trusted for e in events if e.source_ip_trusted is not None}
        if trust == {True, False}:
            group_indicators.append("principal_ip_change")

        context: dict[str, dict[str, Any]] = {}
        principal = events[0].event.principal_id
        targets = {(e.event.resource_type, e.event.resource_id) for e in events}
        if principal != UNKNOWN_PRINCIPAL:
            targets.add(("IAMUser", principal))
        for resource_type, resource_id in sorted(targets):
            state = self._resource_state(resource_type, resource_id)
            if state is not None:
                context[f"{resource_type}/{resource_id}"] = state
        if context.get(f"IAMUser/{principal}", {}).get("admin") is True:
            group_indicators.append("privileged_principal")
        return EventGroup(group_id=group_id(items), events=events, resource_context=context,
                          group_indicators=group_indicators)

    def _resource_state(self, resource_type: str, resource_id: str) -> dict[str, Any] | None:
        if (self._lookup is None or resource_type not in LOOKUP_RESOURCE_TYPES
                or resource_id in ("", "*") or resource_id == UNKNOWN_PRINCIPAL):
            return None
        key = (resource_type, resource_id)
        if key not in self._cache:
            self._cache[key] = self._lookup(resource_type, resource_id)
        return self._cache[key]
