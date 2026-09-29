"""Builds the bounded, sanitized evidence context the Triage model sees.

Only data about THIS incident is included: its events (from the incident's evidence),
its principal and affected resources (read through tools, as the Triage Agent), security
findings for those resources and the Monitor's decision. Every item gets a short ref
(EV1, RS1, PR1, MF1) - the model may cite only these refs.

Never included: credentials/key IDs/secrets, raw database rows, other incidents, prompts,
file paths. Sizes are capped by config/triage_rules.yaml.
"""

import json
from typing import Any

from pydantic import BaseModel

from app.agents.redaction import sanitize, summarize_iam_user
from app.agents.triage.config import TriageConfig
from app.domain.enums import AgentName
from app.domain.incident import IncidentState
from app.domain.triage import ObservedFact
from app.tools.base import ToolRequest
from app.tools.executor import ToolExecutor

LOOKUP_TYPES = ("IAMUser", "EC2Instance", "S3Bucket")


class TriageContext(BaseModel):
    """What the model is given, plus the ref table used to validate and store its answer."""

    payload: dict[str, Any]
    facts: dict[str, ObservedFact]  # ref -> the system-generated fact it stands for
    input_event_ids: list[str]

    def to_json(self) -> str:
        return json.dumps(self.payload, indent=1, ensure_ascii=False, sort_keys=False)


class ContextBuilder:
    def __init__(self, config: TriageConfig, tools: ToolExecutor | None) -> None:
        self._rules = config.context
        self._tools = tools

    def _tool(self, name: str, incident_id: str, **arguments: Any) -> Any:
        if self._tools is None:
            return None
        result = self._tools.execute(ToolRequest(
            tool_name=name, arguments=arguments, requested_by=AgentName.TRIAGE,
            incident_id=incident_id, reason="triage evidence collection"))
        return result.output if result.ok else None

    def build(self, incident: IncidentState) -> TriageContext:
        cap = self._rules.max_string_length
        facts: dict[str, ObservedFact] = {}

        events = sorted((e for e in incident.evidence if e.kind == "event" and e.event_id),
                        key=lambda e: str(e.data.get("timestamp", "")))
        events = events[-self._rules.max_events:]
        event_items = []
        for n, ev in enumerate(events, 1):
            ref, d = f"EV{n}", ev.data
            fact = (f"{d.get('timestamp')} {d.get('event_type')} by {d.get('principal_id')} from "
                    f"{d.get('source_ip')} on {d.get('resource_type')}/{d.get('resource_id')} "
                    f"(source {d.get('source')}, source severity {d.get('severity')})")
            facts[ref] = ObservedFact(ref=ref, kind="event", fact=fact, event_id=ev.event_id,
                                      evidence_id=ev.evidence_id)
            event_items.append({"ref": ref, "timestamp": d.get("timestamp"), "event_type": d.get("event_type"),
                                "source": d.get("source"), "principal": d.get("principal_id"),
                                "source_ip": d.get("source_ip"),
                                "resource": f"{d.get('resource_type')}/{d.get('resource_id')}",
                                "source_severity": d.get("severity"),
                                "monitor_signals": d.get("indicators", [])})

        principal_item = None
        principal = incident.principal_id
        if principal and principal != "unknown":
            state = self._tool("get_iam_entity", incident.incident_id, username=principal)
            if state is not None:
                summary = summarize_iam_user(state.get("state", {}))
                facts["PR1"] = ObservedFact(ref="PR1", kind="principal",
                                            fact=f"IAM user {principal}: {json.dumps(summary)}")
                principal_item = {"ref": "PR1", **summary}

        resource_items = []
        seen = {("IAMUser", principal)}
        for resource in incident.affected_resources:
            key = (resource.resource_type, resource.resource_id)
            if key in seen or len(resource_items) >= self._rules.max_resources:
                continue
            seen.add(key)
            ref = f"RS{len(resource_items) + 1}"
            item: dict[str, Any] = {"ref": ref, "type": resource.resource_type, "id": resource.resource_id}
            if resource.resource_type in LOOKUP_TYPES:
                context = self._tool("get_asset_context", incident.incident_id,
                                     resource_id=resource.resource_id, limit=10)
                if context is not None:
                    state = context.get("state", {})
                    item["current_state"] = (summarize_iam_user(state) if resource.resource_type == "IAMUser"
                                             else {k: v for k, v in state.items() if k != "id"})
                    item["recent_event_types"] = sorted({e["event_type"] for e in context.get("recent_events", [])})
            findings = self._tool("get_security_findings", incident.incident_id,
                                  resource_id=resource.resource_id, limit=5)
            item["security_findings"] = len(findings) if findings is not None else "unavailable"
            facts[ref] = ObservedFact(ref=ref, kind="resource",
                                      fact=f"{resource.resource_type}/{resource.resource_id}: "
                                           f"{json.dumps(sanitize(item.get('current_state', {}), cap))}")
            resource_items.append(item)

        monitor_items = []
        for n, decision in enumerate(d for d in incident.agent_decisions if d.actor == AgentName.MONITOR):
            ref = f"MF{n + 1}"
            facts[ref] = ObservedFact(ref=ref, kind="monitor_finding",
                                      fact=f"Monitor {decision.decision} (confidence {decision.confidence}): "
                                           f"{decision.reasoning}")
            monitor_items.append({"ref": ref, "decision": decision.decision,
                                  "reasoning": decision.reasoning})

        payload = sanitize({
            "incident": {
                "incident_id": incident.incident_id, "title": incident.title,
                "trigger_event_type": incident.event_type, "source": incident.source.value,
                "principal": principal, "source_ip": incident.source_ip,
                "account_id": incident.account_id, "region": incident.region,
                "correlated_event_count": len(incident.related_event_ids),
                # The Monitor's confidence number is deliberately NOT sent: it measures
                # "is this an incident", and a model shown it tends to copy it as its own
                # triage confidence (observed with qwen3:4b).
                "monitor_initial_assessment": {
                    "severity": incident.severity.value,
                    "priority": incident.priority.value if incident.priority else None,
                    "category": incident.category.value,
                    "signals": (incident.normalized_event.get("group_indicators")
                                or incident.normalized_event.get("indicators", [])),
                },
            },
            "events": event_items,
            "principal": principal_item,
            "resources": resource_items,
            "monitor_findings": monitor_items,
            "environment": {"cloud": "simulated AWS account (no real AWS)",
                            "evidence_refs_you_may_cite": sorted(facts)},
        }, cap)
        payload = self._fit(payload)
        cited = set(payload["environment"]["evidence_refs_you_may_cite"])
        return TriageContext(payload=payload, facts={r: f for r, f in facts.items() if r in cited},
                             input_event_ids=[f.event_id for r, f in facts.items()
                                              if f.event_id and r in cited])

    def _fit(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Drop the oldest events until the context fits max_context_chars."""
        while len(json.dumps(payload)) > self._rules.max_context_chars and len(payload["events"]) > 1:
            dropped = payload["events"].pop(0)["ref"]
            refs = payload["environment"]["evidence_refs_you_may_cite"]
            refs.remove(dropped)
        return payload
