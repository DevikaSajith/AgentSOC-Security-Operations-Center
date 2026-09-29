"""Deterministic, incident-scoped evidence collection.

Every item gets a stable ID (EV = event, PR = principal, RS = resource, SF = security
finding, MF = Monitor finding, TR = Triage assessment). Items are built by the SYSTEM from
incident data and read tools used AS THE INVESTIGATOR; the model can only cite their IDs.

Scope: only events listed in incident.related_event_ids, the incident's principal and its
affected resources. Other incidents and unrelated events are never read into the catalog.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.agents.monitor.fingerprint import fingerprint
from app.agents.redaction import GROUND_TRUTH_KEYS, sanitize, summarize_iam_user
from app.domain.enums import AgentName, EventSource
from app.domain.events import SecurityEvent
from app.domain.incident import IncidentState
from app.domain.investigation import EvidenceItem
from app.tools.base import ToolRequest
from app.tools.executor import ToolExecutor

LOOKUP_TYPES = ("IAMUser", "EC2Instance", "S3Bucket")
RESOURCE_SOURCE = {"S3Bucket": "S3", "EC2Instance": "EC2", "IAMUser": "IAM"}
UNSPECIFIED_IP = "0.0.0.0"


@dataclass
class EventFacts:
    """Internal view of one incident event (used for timeline, entities and MITRE)."""

    evidence_id: str
    event_id: str
    timestamp: datetime | None
    event_type: str
    source: str
    principal: str
    source_ip: str
    resource_type: str
    resource_id: str
    account_id: str
    region: str
    details: dict[str, Any]
    indicators: list[str]


@dataclass
class EvidenceCatalog:
    items: dict[str, EvidenceItem] = field(default_factory=dict)  # insertion-ordered
    events: list[EventFacts] = field(default_factory=list)  # chronological
    limitations: list[str] = field(default_factory=list)

    @property
    def event_ids(self) -> list[str]:
        return [e.event_id for e in self.events]

    def observed_ids(self) -> set[str]:
        return {i for i, item in self.items.items() if item.observed}


def _utc(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _event_details(event: SecurityEvent) -> dict[str, Any]:
    """What the source recorded (request parameters / flow fields), minus ground truth."""
    raw = event.raw_event or {}
    if event.source == EventSource.VPC_FLOW_LOGS:
        picked = {k: raw.get(k) for k in ("dstaddr", "dstport", "bytes", "direction", "action")}
    elif isinstance(raw.get("requestParameters"), dict):
        picked = dict(raw["requestParameters"])
    else:
        picked = dict(event.details)
    return {k: v for k, v in picked.items() if v is not None and k not in GROUND_TRUTH_KEYS}


def _describe(e: EventFacts) -> str:
    text = f"{e.event_type} by {e.principal} from {e.source_ip} on {e.resource_type}/{e.resource_id}"
    shown = {k: v for k, v in e.details.items() if not isinstance(v, (dict, list))}
    if shown:
        text += " (" + ", ".join(f"{k}={v}" for k, v in list(shown.items())[:4]) + ")"
    return text


class EvidenceCollector:
    def __init__(self, tools: ToolExecutor | None, max_events: int, max_resources: int,
                 max_string_length: int) -> None:
        self._tools = tools
        self._max_events = max_events
        self._max_resources = max_resources
        self._cap = max_string_length

    def _tool(self, name: str, incident_id: str, **arguments: Any) -> Any:
        if self._tools is None:
            return None
        result = self._tools.execute(ToolRequest(
            tool_name=name, arguments=arguments, requested_by=AgentName.INVESTIGATOR,
            incident_id=incident_id, reason="investigation evidence collection"))
        return result.output if result.ok else None

    # ------------------------------------------------------------------- events
    def _stored_events(self, incident: IncidentState) -> dict[str, SecurityEvent]:
        """Full stored records for the incident's own events, via read tools."""
        wanted, found = set(incident.related_event_ids), {}
        queries: list[tuple[str, dict[str, Any]]] = []
        if incident.principal_id and incident.principal_id != "unknown":
            queries.append(("get_cloudtrail_events", {"principal_id": incident.principal_id, "limit": 500}))
        for r in incident.affected_resources:
            if r.resource_type == "EC2Instance":
                queries.append(("get_network_events", {"resource_id": r.resource_id, "limit": 200}))
        for name, args in queries:
            for raw in self._tool(name, incident.incident_id, **args) or []:
                if raw.get("event_id") in wanted:  # incident-scoped: never keep other events
                    found[raw["event_id"]] = SecurityEvent.model_validate(raw)
        return found

    def _collect_events(self, incident: IncidentState, catalog: EvidenceCatalog) -> None:
        stored = self._stored_events(incident)
        seen_ids, seen_prints, facts, duplicates, from_summary = set(), set(), [], 0, 0
        for ev in incident.evidence:
            if ev.kind != "event" or not ev.event_id or ev.event_id not in incident.related_event_ids:
                continue
            record, data = stored.get(ev.event_id), ev.data
            print_ = fingerprint(record) if record else data.get("fingerprint")
            if ev.event_id in seen_ids or (print_ and print_ in seen_prints):
                duplicates += 1
                continue
            seen_ids.add(ev.event_id)
            if print_:
                seen_prints.add(print_)
            if record is not None:
                facts.append(EventFacts(
                    evidence_id="", event_id=record.event_id, timestamp=record.timestamp,
                    event_type=record.event_type, source=record.source.value, principal=record.user,
                    source_ip=record.source_ip, resource_type=record.resource_type,
                    resource_id=record.resource_id, account_id=record.account_id, region=record.region,
                    details=sanitize(_event_details(record), self._cap),
                    indicators=list(data.get("indicators", []))))
            else:
                from_summary += 1
                facts.append(EventFacts(
                    evidence_id="", event_id=ev.event_id, timestamp=_utc(data.get("timestamp")),
                    event_type=str(data.get("event_type", "unknown")), source=str(data.get("source", "unknown")),
                    principal=str(data.get("principal_id", "unknown")),
                    source_ip=str(data.get("source_ip", UNSPECIFIED_IP)),
                    resource_type=str(data.get("resource_type", "")), resource_id=str(data.get("resource_id", "")),
                    account_id=incident.account_id, region=incident.region, details={},
                    indicators=list(data.get("indicators", []))))
        if duplicates:
            catalog.limitations.append(f"{duplicates} duplicate event record(s) were collapsed.")
        if from_summary:
            catalog.limitations.append(f"{from_summary} event(s) were only available as Monitor summaries "
                                       "(no request details).")
        undated = [f for f in facts if f.timestamp is None]
        if undated:
            catalog.limitations.append(f"{len(undated)} event(s) have no timestamp; they are listed last "
                                       "and their order is unknown.")
        facts.sort(key=lambda f: (f.timestamp is None, f.timestamp or datetime.min.replace(tzinfo=timezone.utc),
                                  f.event_id))
        if len(facts) > self._max_events:
            catalog.limitations.append(f"Only the latest {self._max_events} of {len(facts)} events are included.")
            dated, undated_ = [f for f in facts if f.timestamp], [f for f in facts if not f.timestamp]
            facts = (dated + undated_)[-self._max_events:]
        monitor_evidence = {e.event_id: e.evidence_id for e in incident.evidence if e.kind == "event"}
        for n, f in enumerate(facts, 1):
            f.evidence_id = f"EV{n}"
            network = f.source == EventSource.VPC_FLOW_LOGS.value
            catalog.items[f.evidence_id] = EvidenceItem(
                evidence_id=f.evidence_id, type="network" if network else "event", source=f.source,
                timestamp=f.timestamp, entity=f.principal if f.principal != "unknown" else
                f"{f.resource_type}/{f.resource_id}", description=_describe(f),
                raw_reference={"event_id": f.event_id, "monitor_evidence_id": monitor_evidence.get(f.event_id)},
                confidence=1.0, observed=True)
        catalog.events = facts
        if not any(f.source == EventSource.VPC_FLOW_LOGS.value for f in facts):
            catalog.limitations.append("No network flow (VPC Flow Logs) evidence is available for this incident.")

    # --------------------------------------------------------- state + findings
    def _collect_context(self, incident: IncidentState, catalog: EvidenceCatalog) -> None:
        principal = incident.principal_id
        if principal and principal != "unknown":
            output = self._tool("get_iam_entity", incident.incident_id, username=principal)
            if output is not None:
                summary = summarize_iam_user(output.get("state", {}))
                catalog.items["PR1"] = EvidenceItem(
                    evidence_id="PR1", type="iam", source="IAM", entity=principal,
                    description=(f"Current IAM state of {principal}: role={summary['role']}, "
                                 f"admin={summary['admin']}, access keys active "
                                 f"{summary['access_keys_active']}/{summary['access_keys_total']}"),
                    raw_reference={"resource": f"IAMUser/{principal}", "state": summary},
                    confidence=1.0, observed=True)
        seen, count, findings = {("IAMUser", principal)}, 0, []
        for resource in incident.affected_resources:
            key = (resource.resource_type, resource.resource_id)
            if key in seen or resource.resource_id == "*" or count >= self._max_resources:
                continue
            seen.add(key)
            count += 1
            ref, label = f"RS{count}", f"{resource.resource_type}/{resource.resource_id}"
            state = None
            if resource.resource_type in LOOKUP_TYPES:
                output = self._tool("get_asset_context", incident.incident_id,
                                    resource_id=resource.resource_id, limit=5)
                if output is not None:
                    raw = output.get("state", {})
                    state = (summarize_iam_user(raw) if resource.resource_type == "IAMUser"
                             else sanitize({k: v for k, v in raw.items() if k != "id"}, self._cap))
            description = (f"Current state of {label}: " + ", ".join(f"{k}={v}" for k, v in state.items())
                           if state else f"{label} is referenced by incident events (no state lookup available)")
            catalog.items[ref] = EvidenceItem(
                evidence_id=ref, type="resource", source=RESOURCE_SOURCE.get(resource.resource_type, "Incident"),
                entity=label, description=description,
                raw_reference={"resource": label, "state": state}, confidence=1.0 if state else 0.5,
                observed=state is not None)
            findings += [(label, f) for f in self._tool("get_security_findings", incident.incident_id,
                                                        resource_id=resource.resource_id, limit=5) or []]
        for n, (label, finding) in enumerate(findings, 1):
            ref = f"SF{n}"
            catalog.items[ref] = EvidenceItem(
                evidence_id=ref, type="security_finding", source=str(finding.get("source")),
                timestamp=_utc(finding.get("timestamp")), entity=label,
                description=f"{finding.get('source')} finding {finding.get('event_type')} on {label} "
                            f"(severity {finding.get('severity')})",
                raw_reference={"event_id": finding.get("event_id")}, confidence=1.0, observed=True)
        if not findings:
            catalog.limitations.append("No GuardDuty or Security Hub findings exist for the affected "
                                       "resources in this (simulated) environment.")
        if any(i.type in ("iam", "resource") and i.observed for i in catalog.items.values()):
            catalog.limitations.append("IAM and resource states are CURRENT simulated states captured at "
                                       "investigation time, not their state when each event happened.")
        if any(f.event_type == "CreateAccessKey" for f in catalog.events):
            catalog.limitations.append("Access key identifiers are redacted; later activity cannot be tied "
                                       "to a specific key.")

    def _collect_prior_assessments(self, incident: IncidentState, catalog: EvidenceCatalog) -> None:
        monitor = [d for d in incident.agent_decisions if d.actor == AgentName.MONITOR]
        for n, decision in enumerate(monitor, 1):
            catalog.items[f"MF{n}"] = EvidenceItem(
                evidence_id=f"MF{n}", type="monitor_finding", source="Monitor Agent", timestamp=decision.timestamp,
                entity=incident.principal_id or incident.incident_id,
                description=f"Monitor {decision.decision}: {decision.reasoning}"[:self._cap],
                raw_reference={"decision_id": decision.decision_id},
                confidence=decision.confidence, observed=False)
        triage = incident.triage
        if triage is not None:
            catalog.items["TR1"] = EvidenceItem(
                evidence_id="TR1", type="triage_assessment", source="Triage Agent", timestamp=triage.timestamp,
                entity=incident.incident_id,
                description=(f"Triage ({triage.method.value}): {triage.severity.value}/{triage.priority.value}/"
                             f"{triage.category.value}, '{triage.interpretation.classification}', "
                             f"next step {triage.recommended_next_step.value}"),
                raw_reference={"run_id": triage.run_id}, confidence=triage.confidence, observed=False)

    def collect(self, incident: IncidentState) -> EvidenceCatalog:
        catalog = EvidenceCatalog()
        self._collect_events(incident, catalog)
        self._collect_context(incident, catalog)
        self._collect_prior_assessments(incident, catalog)
        return catalog
