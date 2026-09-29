"""Assembles the bounded investigation context from deterministic analysis.

The model receives: the incident header, the triage summary (context only), the evidence
catalog, the timeline, entities/relationships, MITRE candidates, stage hints and known
limitations - all scoped to one incident, redacted and size-capped.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.agents.investigator.config import InvestigatorConfig
from app.agents.investigator.entities import build_entities
from app.agents.investigator.evidence import EvidenceCatalog, EvidenceCollector
from app.agents.investigator.mitre import candidate_techniques
from app.agents.investigator.timeline import build_timeline
from app.agents.redaction import sanitize
from app.domain.enums import AgentName
from app.domain.incident import IncidentState
from app.domain.investigation import Entity, Relationship, TimelineEntry
from app.knowledge.mitre import load_techniques
from app.tools.base import ToolRequest
from app.tools.executor import ToolExecutor


@dataclass
class InvestigationContext:
    catalog: EvidenceCatalog
    timeline: list[TimelineEntry]
    entities: list[Entity]
    relationships: list[Relationship]
    mitre_candidates: list[dict[str, Any]]
    payload: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(self.payload, indent=1, ensure_ascii=False, default=str)

    @property
    def evidence_ids(self) -> set[str]:
        return set(self.catalog.items)

    @property
    def timeline_ids(self) -> set[str]:
        return {t.evidence_id for t in self.timeline}


def _ts(value: Any) -> str | None:
    return value.isoformat() if value else None


class InvestigationContextBuilder:
    def __init__(self, config: InvestigatorConfig, tools: ToolExecutor | None, config_dir: Path) -> None:
        self._config = config
        self._tools = tools
        self._config_dir = config_dir

    def _mitre_lookup(self, incident_id: str):
        def lookup(technique_id: str) -> dict[str, Any] | None:
            if self._tools is None:
                return None
            result = self._tools.execute(ToolRequest(
                tool_name="get_mitre_technique", arguments={"technique_id": technique_id},
                requested_by=AgentName.INVESTIGATOR, incident_id=incident_id,
                reason="MITRE candidate details"))
            return result.output if result.ok else None
        return lookup

    def build(self, incident: IncidentState) -> InvestigationContext:
        rules = self._config.context
        catalog = EvidenceCollector(self._tools, rules.max_events, rules.max_resources,
                                    rules.max_string_length).collect(incident)
        timeline = build_timeline(catalog)
        entities, relationships = build_entities(catalog)
        candidates = candidate_techniques(catalog, self._config_dir, self._mitre_lookup(incident.incident_id))
        names = {e.entity_id: f"{e.type}:{e.value}" for e in entities}
        triage = incident.triage
        stage_hints = {e.event_type: self._config.stage_by_event_type[e.event_type].value
                       for e in catalog.events if e.event_type in self._config.stage_by_event_type}
        payload = sanitize({
            "incident": {"incident_id": incident.incident_id, "title": incident.title,
                         "principal": incident.principal_id, "trigger_event_type": incident.event_type,
                         "account_id": incident.account_id, "region": incident.region,
                         "correlated_event_count": len(incident.related_event_ids)},
            "triage_summary_for_context_only": None if triage is None else {
                "ref": "TR1", "severity": triage.severity.value, "priority": triage.priority.value,
                "category": triage.category.value, "classification": triage.interpretation.classification},
            "evidence": [{"id": i.evidence_id, "type": i.type, "source": i.source, "timestamp": _ts(i.timestamp),
                          "entity": i.entity, "observed": i.observed, "description": i.description}
                         for i in catalog.items.values()],
            "timeline": [{"id": t.evidence_id, "time": _ts(t.timestamp), "event": t.event_type,
                          "gap_seconds": t.seconds_since_previous, "shares_with_previous": t.shared_with_previous}
                         for t in timeline],
            "entities": [{"id": e.entity_id, "type": e.type, "value": e.value, "evidence": e.evidence_ids,
                          **({"attributes": e.attributes} if e.attributes else {})} for e in entities],
            "relationships": [{"from": names[r.source], "relation": r.relation, "to": names[r.target],
                               "evidence": r.evidence_ids, "certainty": r.certainty.value} for r in relationships],
            "mitre_candidates": [{"technique_id": c["technique_id"], "name": c["name"], "tactic": c["tactic"],
                                  "matched_evidence": c["matched_evidence_ids"]} for c in candidates],
            "stage_hints_by_event_type": stage_hints,
            "known_limitations": catalog.limitations,
            "allowed": {"evidence_ids": list(catalog.items),
                        "timeline_evidence_ids": [t.evidence_id for t in timeline],
                        "mitre_technique_ids": sorted(load_techniques(self._config_dir))},
        }, rules.max_string_length)
        payload = self._fit(payload, catalog)
        return InvestigationContext(catalog, timeline, entities, relationships, candidates, payload)

    def _fit(self, payload: dict[str, Any], catalog: EvidenceCatalog) -> dict[str, Any]:
        """Trim relationships, then entity detail, then descriptions until the size cap fits."""
        cap = self._config.context.max_context_chars
        if len(json.dumps(payload, default=str)) > cap:
            payload["relationships"] = payload["relationships"][:20]
        if len(json.dumps(payload, default=str)) > cap:
            for entity in payload["entities"]:
                entity.pop("attributes", None)
        while len(json.dumps(payload, default=str)) > cap:
            longest = max(payload["evidence"], key=lambda e: len(e["description"]))
            if len(longest["description"]) <= 60:
                break
            longest["description"] = longest["description"][:len(longest["description"]) // 2] + "…"
        if len(json.dumps(payload, default=str)) > cap:
            catalog.limitations.append("Context was truncated to fit the model's limit.")
        return payload
