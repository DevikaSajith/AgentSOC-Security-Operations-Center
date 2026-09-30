"""Deterministic compliance analysis (everything here happens BEFORE the LLM is asked anything).

    investigated incident -> evidence catalog (reuses the Investigator's catalog) -> affected assets
      -> data classification (configured metadata only) -> candidate controls -> configured
      framework mappings -> matched violation rules -> matched reporting rules -> standing unknowns

Read tools are used AS THE COMPLIANCE AGENT (get_resource) for the current state of assets.
"""

from dataclasses import dataclass, field
from typing import Any

from app.agents.compliance.config import ComplianceSettings, Control
from app.agents.redaction import sanitize, summarize_iam_user
from app.domain.compliance import (
    AffectedAsset,
    AffectedData,
    DataClassification,
    RuleMatch,
)
from app.domain.enums import AgentName, Severity
from app.domain.incident import IncidentState
from app.domain.investigation import EvidenceItem
from app.tools.base import ToolRequest
from app.tools.executor import ToolExecutor

SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
LOOKUP_TYPES = ("IAMUser", "EC2Instance", "S3Bucket")
OBSERVED_PREFIXES = ("EV", "PR", "RS", "SF", "AS")
NOT_CLASSIFIED = "Not defined in compliance_mapping.yaml (never inferred from the resource name)"


@dataclass
class CandidateControl:
    control_id: str
    control: Control
    matched_evidence_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class ComplianceAnalysis:
    evidence: dict[str, EvidenceItem]
    assets: list[AffectedAsset]
    data: list[AffectedData]
    candidates: dict[str, CandidateControl]
    violation_matches: list[RuleMatch]
    reporting_matches: list[RuleMatch]
    standing_unknowns: list[str]
    event_ids: list[str]

    def observed_ids(self) -> set[str]:
        return {i for i, e in self.evidence.items() if e.observed}


def _asset_key(resource_type: str, resource_id: str) -> str:
    return f"{resource_type}/{resource_id}"


class ComplianceAnalyzer:
    def __init__(self, settings: ComplianceSettings, tools: ToolExecutor | None) -> None:
        self._mapping = settings.mapping
        self._config = settings.config
        self._tools = tools

    def _state(self, incident_id: str, resource_type: str, resource_id: str) -> dict[str, Any] | None:
        if self._tools is None or resource_type not in LOOKUP_TYPES:
            return None
        result = self._tools.execute(ToolRequest(
            tool_name="get_resource", requested_by=AgentName.COMPLIANCE, incident_id=incident_id,
            arguments={"resource_type": resource_type, "resource_id": resource_id},
            reason="compliance asset state"))
        if not result.ok:
            return None
        state = result.output.get("state", {})
        return summarize_iam_user(state) if resource_type == "IAMUser" else sanitize(
            {k: v for k, v in state.items() if k != "id"}, self._config.context.max_string_length)

    # ------------------------------------------------------------------ evidence
    def _evidence(self, incident: IncidentState, assets: list[AffectedAsset]) -> dict[str, EvidenceItem]:
        inv = incident.investigation
        assert inv is not None
        cap = self._config.context.max_string_length
        items: dict[str, EvidenceItem] = {}
        # Investigator's catalog first (stable ids): observed telemetry/state and earlier opinions.
        for item in inv.evidence:
            items[item.evidence_id] = item.model_copy(update={"description": item.description[:cap]})
        for n, finding in enumerate(inv.findings, 1):
            items[f"IF{n}"] = EvidenceItem(
                evidence_id=f"IF{n}", type="investigation_finding", source="Investigator Agent",
                entity=incident.principal_id or incident.incident_id,
                description=f"{finding.type.value} ({finding.classification.value}): {finding.statement}"[:cap],
                raw_reference={"finding_id": finding.finding_id, "cites": finding.evidence_ids},
                confidence=finding.confidence, observed=False)
        confirmed = [t for t in inv.mitre_techniques if t.status.value == "confirmed"]
        for n, technique in enumerate(confirmed, 1):
            items[f"MT{n}"] = EvidenceItem(
                evidence_id=f"MT{n}", type="mitre_technique", source="Investigator Agent",
                entity=technique.technique_id,
                description=f"{technique.technique_id} {technique.technique_name} ({technique.tactic}), "
                            f"confirmed by the backend from {', '.join(technique.evidence_ids)}"[:cap],
                raw_reference={"technique_id": technique.technique_id}, confidence=technique.confidence,
                observed=False)
        for asset in assets:
            state = ", ".join(f"{k}={v}" for k, v in asset.state.items()) or "no state available"
            items[asset.asset_id] = EvidenceItem(
                evidence_id=asset.asset_id, type="asset", source="Simulated cloud", entity=asset.identifier,
                description=f"Asset {asset.identifier}: classification={asset.classification.value}, "
                            f"environment={asset.environment or 'unknown'}, owner={asset.owner or 'unknown'}, "
                            f"current state: {state}"[:cap],
                raw_reference={"asset": asset.identifier}, confidence=1.0, observed=True)
        return items

    # -------------------------------------------------------------------- assets
    def _assets(self, incident: IncidentState) -> list[AffectedAsset]:
        inv = incident.investigation
        assert inv is not None
        resources: dict[str, tuple[str, str]] = {}
        for resource in incident.affected_resources:
            if resource.resource_id and resource.resource_id != "*":
                resources[_asset_key(resource.resource_type, resource.resource_id)] = (
                    resource.resource_type, resource.resource_id)
        assets = []
        for n, (key, (resource_type, resource_id)) in enumerate(sorted(resources.items()), 1):
            meta = self._mapping.asset_metadata.get(key)
            related = [e.evidence_id for e in inv.evidence
                       if e.observed and (key in e.description or e.entity == key
                                          or (resource_type == "IAMUser" and e.entity == resource_id))]
            assets.append(AffectedAsset(
                asset_id=f"AS{n}", asset_type=resource_type, identifier=key,
                classification=meta.classification if meta else DataClassification.UNKNOWN,
                classification_basis=meta.basis if meta else NOT_CLASSIFIED,
                environment=meta.environment if meta else None, owner=None,
                state=self._state(incident.incident_id, resource_type, resource_id) or {},
                evidence_ids=related))
        return assets

    # ---------------------------------------------------------------- candidates
    def _candidates(self, incident: IncidentState, assets: list[AffectedAsset]) -> dict[str, CandidateControl]:
        inv = incident.investigation
        assert inv is not None
        events = [(t.evidence_id, t.event_type) for t in inv.timeline]
        mitre = {t.technique_id: f"{t.technique_id}" for t in inv.mitre_techniques}
        candidates: dict[str, CandidateControl] = {}
        for control_id, control in self._mapping.controls.items():
            trig, matched, reasons = control.triggers, [], []
            if trig.always:
                reasons.append("always assessed")
            for evidence_id, event_type in events:
                if event_type in trig.event_types:
                    matched.append(evidence_id)
                    reasons.append(f"event {event_type}")
            for technique_id in mitre:
                if technique_id in trig.mitre:
                    reasons.append(f"MITRE {technique_id}")
            for asset in assets:
                if asset.asset_type in trig.resource_types:
                    matched.append(asset.asset_id)
                    reasons.append(f"resource type {asset.asset_type}")
            if trig.always or matched or any(t in trig.mitre for t in mitre):
                candidates[control_id] = CandidateControl(control_id, control, sorted(set(matched)),
                                                          sorted(set(reasons)))
        return candidates

    # --------------------------------------------------------------------- rules
    def _violation_matches(self, incident: IncidentState, candidates: dict[str, CandidateControl]) -> list[RuleMatch]:
        inv = incident.investigation
        assert inv is not None
        indicators = set(incident.normalized_event.get("group_indicators")
                         or incident.normalized_event.get("indicators") or [])
        matches = []
        for rule in self._mapping.violation_rules:
            if rule.control not in candidates or not set(rule.requires_indicators) <= indicators:
                continue
            evidence_ids = [t.evidence_id for t in inv.timeline if t.event_type in rule.requires_event_types]
            if evidence_ids:
                matches.append(RuleMatch(rule_id=rule.id, description=rule.description,
                                         control_id=rule.control, evidence_ids=evidence_ids))
        return matches

    def _reporting_matches(self, incident: IncidentState, candidates: dict[str, CandidateControl],
                           data: list[AffectedData]) -> list[RuleMatch]:
        classes = {d.classification for d in data}
        matches = []
        for rule in self._mapping.reporting_rules:
            if SEVERITY_RANK[incident.severity] < SEVERITY_RANK[rule.min_severity]:
                continue
            if rule.controls_any and not set(rule.controls_any) & set(candidates):
                continue
            if rule.data_classifications_any and not set(rule.data_classifications_any) & classes:
                continue
            matches.append(RuleMatch(rule_id=rule.id, description=rule.description,
                                     requirement=rule.requirement))
        return matches

    def _standing_unknowns(self, assets: list[AffectedAsset]) -> list[str]:
        unknowns = []
        unclassified = [a.identifier for a in assets if a.classification == DataClassification.UNKNOWN]
        if unclassified:
            unknowns.append("Data classification is unavailable for: " + ", ".join(unclassified) + ".")
        if any(a.owner is None for a in assets):
            unknowns.append(self._config.standing_unknowns["asset_owner"])
        for key in ("jurisdiction", "retention_policy", "framework_applicability"):
            unknowns.append(self._config.standing_unknowns[key])
        return unknowns

    # ------------------------------------------------------------------- public
    def analyze(self, incident: IncidentState) -> ComplianceAnalysis:
        assets = self._assets(incident)
        data = [AffectedData(asset_id=a.asset_id, identifier=a.identifier, classification=a.classification,
                             basis=a.classification_basis)
                for a in assets if a.classification not in (DataClassification.UNKNOWN,)]
        candidates = self._candidates(incident, assets)
        return ComplianceAnalysis(
            evidence=self._evidence(incident, assets), assets=assets, data=data, candidates=candidates,
            violation_matches=self._violation_matches(incident, candidates),
            reporting_matches=self._reporting_matches(incident, candidates, data),
            standing_unknowns=self._standing_unknowns(assets),
            event_ids=[e for e in (incident.investigation.input_event_ids if incident.investigation else [])])
