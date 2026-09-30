"""Deterministic remediation analysis (everything here happens BEFORE the LLM is asked anything).

    compliance-assessed incident -> affected resources -> for each policy action that fits the resource type:
      protected? -> current cloud state (read tool) -> applicable now? (already remediated?) ->
      relevant to the incident evidence? -> candidate (exact tool arguments resolved by the backend)

The model may only choose among the candidates built here; it cannot add an action or a target.
"""

from dataclasses import dataclass, field
from typing import Any

from app.agents.remediation.config import RemediationPolicy
from app.agents.remediation.state import (
    fingerprint,
    is_applicable,
    is_remediated,
    read_state,
    safe_summary,
    target_label,
)
from app.domain.enums import Severity
from app.domain.incident import IncidentState
from app.domain.investigation import EvidenceItem
from app.domain.remediation import RemediationAction
from app.tools.executor import ToolExecutor

OBSERVED_PREFIXES = ("EV", "PR", "RS", "SF", "AS", "CS")


@dataclass
class Candidate:
    candidate_id: str
    action: RemediationAction
    target: str
    resource_type: str
    resource_id: str
    arguments: dict[str, Any]
    risk: Severity
    description: str
    state: dict[str, Any]  # safe summary (never key ids)
    fingerprint: str
    evidence_ids: list[str]
    reasons: list[str]
    rollback_available: bool
    rollback_description: str


@dataclass
class RemediationAnalysis:
    evidence: dict[str, EvidenceItem]
    candidates: list[Candidate]
    excluded: list[str] = field(default_factory=list)  # candidates refused by policy/state, with the reason
    already_remediated: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)

    def observed_ids(self) -> set[str]:
        return {i for i, e in self.evidence.items() if e.observed}

    def find(self, action: RemediationAction, target: str | None) -> Candidate | None:
        return next((c for c in self.candidates if c.action == action and c.target == target), None)


class RemediationAnalyzer:
    def __init__(self, policy: RemediationPolicy, tools: ToolExecutor | None) -> None:
        self._policy = policy
        self._tools = tools

    def analyze(self, incident: IncidentState) -> RemediationAnalysis:
        compliance, inv = incident.compliance, incident.investigation
        assert compliance is not None and inv is not None
        cap = self._policy.context.max_string_length
        evidence: dict[str, EvidenceItem] = {
            e.evidence_id: e.model_copy(update={"description": e.description[:cap]}) for e in compliance.evidence}
        analysis = RemediationAnalysis(evidence=evidence, candidates=[], event_ids=list(inv.input_event_ids))
        indicators = set(incident.normalized_event.get("group_indicators")
                         or incident.normalized_event.get("indicators") or [])
        resources: dict[str, tuple[str, str]] = {}
        for resource in incident.affected_resources:
            if resource.resource_id and resource.resource_id != "*":
                resources[target_label(resource.resource_type, resource.resource_id)] = (
                    resource.resource_type, resource.resource_id)
        state_counter = 0
        for target, (resource_type, resource_id) in sorted(resources.items()):
            actions = [(n, p) for n, p in self._policy.actions.items() if p.resource_type == resource_type]
            if not actions:
                continue
            state = read_state(self._tools, incident.incident_id, resource_type, resource_id)
            if state is None:
                analysis.excluded.append(f"{target}: not found in the current cloud state (invalid target)")
                continue
            state_counter += 1
            state_id = f"CS{state_counter}"
            summary = safe_summary(resource_type, state, cap)
            evidence[state_id] = EvidenceItem(
                evidence_id=state_id, type="cloud_state", source="Simulated cloud (read now)", entity=target,
                description=("Current state of " + target + ": "
                             + ", ".join(f"{k}={v}" for k, v in summary.items()))[:cap],
                raw_reference={"resource": target}, confidence=1.0, observed=True)
            for name, policy in actions:
                label = f"{name} on {target}"
                if not policy.enabled:
                    analysis.excluded.append(f"{label}: disabled by policy")
                elif target in self._policy.protected_resources:
                    analysis.excluded.append(f"{label}: protected resource ({self._policy.protected_resources[target]})")
                elif is_remediated(state, policy):
                    analysis.already_remediated.append(f"{label}: the target is already in the desired state")
                elif not is_applicable(state, policy):
                    analysis.excluded.append(f"{label}: not applicable to the current state")
                else:
                    relevant, reasons = self._relevance(incident, policy, resource_type, resource_id, indicators)
                    if not relevant:
                        analysis.excluded.append(f"{label}: no incident evidence involves this target")
                        continue
                    evidence_ids = self._evidence_for(incident, policy, target, resource_id, state_id)
                    analysis.candidates.append(Candidate(
                        candidate_id=f"C{len(analysis.candidates) + 1}", action=RemediationAction(name),
                        target=target, resource_type=resource_type, resource_id=resource_id,
                        arguments={policy.argument: resource_id}, risk=policy.risk, description=policy.description,
                        state=summary, fingerprint=fingerprint(state, policy.fingerprint_fields),
                        evidence_ids=evidence_ids, reasons=reasons, rollback_available=policy.rollback_available,
                        rollback_description=policy.rollback_description))
        return analysis

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _matches(entry_principal: str, entry_resource: str, resource_id: str) -> bool:
        return entry_principal == resource_id or entry_resource == resource_id or entry_resource.endswith("/" + resource_id)

    def _relevance(self, incident: IncidentState, policy: Any, resource_type: str, resource_id: str,
                   indicators: set[str]) -> tuple[bool, list[str]]:
        inv = incident.investigation
        assert inv is not None
        reasons: list[str] = []
        if policy.relevant_event_types:
            hits = sorted({t.event_type for t in inv.timeline if t.event_type in policy.relevant_event_types
                           and self._matches(t.principal, t.resource, resource_id)})
            if not hits:
                return False, []
            reasons.append("incident events involving the target: " + ", ".join(hits))
        if policy.requires_indicators_any:
            hit = sorted(indicators & set(policy.requires_indicators_any))
            if not hit:
                return False, []
            reasons.append("monitor indicators: " + ", ".join(hit))
        reasons.append(f"the target currently satisfies {policy.requires_state}")
        return True, reasons

    def _evidence_for(self, incident: IncidentState, policy: Any, target: str, resource_id: str,
                      state_id: str) -> list[str]:
        inv, compliance = incident.investigation, incident.compliance
        assert inv is not None and compliance is not None
        ids = [state_id]
        ids += [a.asset_id for a in compliance.affected_assets if a.identifier == target]
        ids += [t.evidence_id for t in inv.timeline if t.event_type in policy.relevant_event_types
                and self._matches(t.principal, t.resource, resource_id)]
        ids += [e.evidence_id for e in inv.evidence if e.observed and e.entity in (resource_id, target)]
        return list(dict.fromkeys(i for i in ids if i in self._evidence_keys(compliance, state_id)))[:10]

    @staticmethod
    def _evidence_keys(compliance: Any, state_id: str) -> set[str]:
        return {e.evidence_id for e in compliance.evidence} | {state_id}
