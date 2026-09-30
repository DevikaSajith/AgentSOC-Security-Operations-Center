"""Bounded, redacted, incident-scoped context for the Remediation model.

Contains: the incident header, Triage / Investigation / Compliance summaries, the evidence catalog, the
affected assets, the CANDIDATE ACTIONS the backend built (with the current state of each target and the
policy risk), what the backend refused and why, and the validation rules. It never contains other
incidents, credentials, access-key ids, unrelated cloud resources, raw database contents or file paths.
"""

import json
from dataclasses import dataclass
from typing import Any

from app.agents.redaction import sanitize
from app.agents.remediation.analysis import RemediationAnalysis, RemediationAnalyzer
from app.agents.remediation.config import RemediationPolicy
from app.domain.incident import IncidentState
from app.tools.executor import ToolExecutor

EVIDENCE_PRIORITY = ("CS", "AS", "IF", "MT", "PR", "RS", "SF", "TR", "MF", "EV")


@dataclass
class RemediationContext:
    analysis: RemediationAnalysis
    payload: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(self.payload, indent=1, ensure_ascii=False, default=str)

    @property
    def evidence_ids(self) -> set[str]:
        return {e["id"] for e in self.payload["evidence"]}


def _prefix(evidence_id: str) -> str:
    return evidence_id.rstrip("0123456789")


class RemediationContextBuilder:
    def __init__(self, policy: RemediationPolicy, tools: ToolExecutor | None) -> None:
        self._policy = policy
        self._analyzer = RemediationAnalyzer(policy, tools)

    def build(self, incident: IncidentState) -> RemediationContext:
        rules = self._policy.context
        analysis = self._analyzer.analyze(incident)
        inv, triage, comp = incident.investigation, incident.triage, incident.compliance
        assert inv is not None and comp is not None

        ordered = sorted(analysis.evidence.values(),
                         key=lambda e: (EVIDENCE_PRIORITY.index(_prefix(e.evidence_id))
                                        if _prefix(e.evidence_id) in EVIDENCE_PRIORITY else 99, e.evidence_id))
        # candidates' own evidence must survive trimming
        must_keep = {i for c in analysis.candidates for i in c.evidence_ids}
        kept = [e for e in ordered if e.evidence_id in must_keep]
        kept += [e for e in ordered if e.evidence_id not in must_keep][:max(0, rules.max_evidence_items - len(kept))]
        kept.sort(key=lambda e: ordered.index(e))
        evidence = [{"id": e.evidence_id, "type": e.type, "source": e.source, "observed": e.observed,
                     "entity": e.entity, "description": e.description} for e in kept]
        kept_ids = {e["id"] for e in evidence}

        candidates = [{
            "candidate_id": c.candidate_id, "action": c.action.value, "target": c.target,
            "what_it_does": c.description, "policy_risk": c.risk.value, "requires_human_approval": True,
            "rollback_available": c.rollback_available, "current_state": c.state,
            "engaged_because": c.reasons, "evidence_hint": [i for i in c.evidence_ids if i in kept_ids],
        } for c in analysis.candidates]
        payload = sanitize({
            "incident": {"incident_id": incident.incident_id, "title": incident.title,
                         "principal": incident.principal_id, "severity": incident.severity.value,
                         "category": incident.category.value, "account_id": incident.account_id,
                         "region": incident.region},
            "triage_summary": None if triage is None else {
                "classification": triage.interpretation.classification,
                "recommended_next_step": triage.recommended_next_step.value},
            "investigation_summary": {
                "summary": inv.summary, "confidence": inv.confidence,
                "findings": [f"{f.finding_id} ({f.type.value}, {f.classification.value}): {f.statement}"
                             for f in inv.findings],
                "unknowns": inv.unknowns},
            "compliance_summary": {
                "overall_status": comp.overall_status.value, "summary": comp.summary,
                "controls": [f"{c.control_id}: {c.status.value}" for c in comp.controls],
                "control_gaps": [g.control_id for g in comp.control_gaps],
                "potential_violations": [f"{v.control_id} ({v.rule_id or 'no rule'}): {v.status.value}"
                                         for v in comp.potential_violations],
                "reporting_status": comp.reporting_status.value,
                "unknowns": comp.unknowns},
            "assets": [{"id": a.asset_id, "identifier": a.identifier, "classification": a.classification.value,
                        "environment": a.environment} for a in comp.affected_assets],
            "evidence": evidence,
            "candidate_actions": candidates,
            "not_available": {"refused_by_backend": analysis.excluded,
                              "already_in_desired_state": analysis.already_remediated},
            "policy": {"every_action_needs_human_approval": True,
                       "you_cannot_execute_anything": True,
                       "note": "The backend, not you, resolves the tool arguments, sets the final risk and "
                               "requests approval; a human decides; a kill switch may block execution."},
            "allowed": {
                "actions": sorted({c.action.value for c in analysis.candidates} | {"no_action"}),
                "targets": sorted({c.target for c in analysis.candidates}),
                "evidence_ids": [e["id"] for e in evidence]},
            "rules_your_answer_must_follow": self._rules_text(),
        }, rules.max_string_length)
        payload = self._fit(payload)
        return RemediationContext(analysis, payload)

    def _rules_text(self) -> list[str]:
        p = self._policy.policy
        return [
            "Choose exactly ONE entry of candidate_actions (copy its action and target exactly) or no_action. "
            "Never invent an action, a target, an argument or evidence.",
            f"For an action, cite at least {p.min_evidence_for_action} evidence id from allowed.evidence_ids, of "
            f"which at least {p.min_observed_for_action} is OBSERVED (AS, CS, EV, PR, RS, SF). IF/MT/MF/TR are "
            "earlier agents' opinions, not facts.",
            "Copy the OBSERVED ids from the chosen candidate's evidence_hint (CS/AS/EV...) into evidence_ids; an answer that "
            "cites only IF/MT/MF/TR ids is rejected.",
            "Prefer the LEAST DISRUPTIVE candidate that addresses the incident; do not pick several. Use "
            "no_action (target null, evidence_ids may be empty) when evidence is insufficient, the action would "
            "be unsafe or unnecessary, information is missing, or a human should decide first. Do not force an action.",
            "risk_level, requires_approval and rollback_available are checked against the backend policy and "
            "corrected if wrong; requires_approval must be true for every action.",
            "reason and expected_effect are short plain sentences. No commands, code, CLI, SQL or URLs. "
            "List what you do not know under unknowns (use [] if nothing).",
        ]

    def _fit(self, payload: dict[str, Any]) -> dict[str, Any]:
        cap = self._policy.context.max_context_chars
        size = lambda: len(json.dumps(payload, default=str))  # noqa: E731
        protected = {i for c in payload["candidate_actions"] for i in c["evidence_hint"]}
        while size() > cap and len(payload["evidence"]) > 8:
            drop = next((i for i in range(len(payload["evidence"]) - 1, -1, -1)
                         if payload["evidence"][i]["id"] not in protected), None)
            if drop is None:
                break
            payload["evidence"].pop(drop)
        kept = {e["id"] for e in payload["evidence"]}
        payload["allowed"]["evidence_ids"] = [i for i in payload["allowed"]["evidence_ids"] if i in kept]
        return payload
