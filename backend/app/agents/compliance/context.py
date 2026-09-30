"""Bounded, redacted, incident-scoped context for the Compliance model.

Contains: the incident header, Triage and Investigation summaries, the evidence catalog, affected
assets with their configured classification, candidate controls WITH their configured framework
mappings, matched configured rules, standing unknowns and the validation rules. Never contains
other incidents, credentials, key ids, prompts or file paths.
"""

import json
from dataclasses import dataclass
from typing import Any

from app.agents.compliance.analysis import ComplianceAnalysis, ComplianceAnalyzer
from app.agents.compliance.config import ComplianceSettings
from app.agents.redaction import sanitize
from app.domain.incident import IncidentState
from app.tools.executor import ToolExecutor

EVIDENCE_PRIORITY = ("AS", "IF", "MT", "PR", "RS", "SF", "TR", "MF", "EV")


@dataclass
class ComplianceContext:
    analysis: ComplianceAnalysis
    payload: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(self.payload, indent=1, ensure_ascii=False, default=str)

    @property
    def evidence_ids(self) -> set[str]:
        return {e["id"] for e in self.payload["evidence"]}


def _prefix(evidence_id: str) -> str:
    return evidence_id.rstrip("0123456789")


class ComplianceContextBuilder:
    def __init__(self, settings: ComplianceSettings, tools: ToolExecutor | None) -> None:
        self._settings = settings
        self._analyzer = ComplianceAnalyzer(settings, tools)

    def build(self, incident: IncidentState) -> ComplianceContext:
        rules = self._settings.config.context
        mapping = self._settings.mapping
        analysis = self._analyzer.analyze(incident)
        inv, triage = incident.investigation, incident.triage
        assert inv is not None

        ordered = sorted(analysis.evidence.values(),
                         key=lambda e: (EVIDENCE_PRIORITY.index(_prefix(e.evidence_id))
                                        if _prefix(e.evidence_id) in EVIDENCE_PRIORITY else 99, e.evidence_id))
        kept = ordered[:rules.max_evidence_items]
        evidence = [{"id": e.evidence_id, "type": e.type, "source": e.source, "observed": e.observed,
                     "entity": e.entity, "description": e.description} for e in kept]

        candidates = []
        for control_id, cand in analysis.candidates.items():
            candidates.append({
                "control_id": control_id, "name": cand.control.name, "description": cand.control.description,
                "engaged_because": cand.reasons, "evidence_hint": [e for e in cand.matched_evidence_ids
                                                                  if e in {k["id"] for k in evidence}],
                "framework_mappings": {fw: [{"id": c.id, "title": c.title} for c in controls]
                                       for fw, controls in cand.control.frameworks.items()}})
        payload = sanitize({
            "incident": {"incident_id": incident.incident_id, "title": incident.title,
                         "principal": incident.principal_id, "severity_after_triage": incident.severity.value,
                         "category": incident.category.value, "account_id": incident.account_id,
                         "region": incident.region},
            "triage_summary": None if triage is None else {
                "classification": triage.interpretation.classification,
                "recommended_next_step": triage.recommended_next_step.value},
            "investigation_summary": {
                "summary": inv.summary, "confidence": inv.confidence,
                "confirmed_findings": [f"{f.finding_id} ({f.type.value}, {f.classification.value}): {f.statement}"
                                       for f in inv.findings],
                "unknowns": inv.unknowns, "limitations": inv.limitations},
            "evidence": evidence,
            "assets": [{"id": a.asset_id, "type": a.asset_type, "identifier": a.identifier,
                        "classification": a.classification.value, "classification_basis": a.classification_basis,
                        "environment": a.environment, "owner": "unknown"} for a in analysis.assets],
            "candidate_controls": candidates,
            "matched_violation_rules": [{"rule_id": m.rule_id, "control_id": m.control_id,
                                         "description": m.description, "evidence": m.evidence_ids}
                                        for m in analysis.violation_matches],
            "matched_reporting_rules": [{"rule_id": m.rule_id, "requirement": m.requirement,
                                         "description": m.description} for m in analysis.reporting_matches],
            "standing_unknowns_backend_will_add": analysis.standing_unknowns,
            "allowed": {
                "evidence_ids": [e["id"] for e in evidence],
                "control_ids": list(analysis.candidates),
                "frameworks": {k: v.name for k, v in mapping.frameworks.items()},
                "recommendation_types": [t.value for t in self._settings.config.policy.recommendation_types],
                "violation_rule_ids_matched": [m.rule_id for m in analysis.violation_matches],
                "reporting_rule_ids_matched": [m.rule_id for m in analysis.reporting_matches]},
            "rules_your_answer_must_follow": self._rules_text(bool(analysis.violation_matches)),
        }, rules.max_string_length)
        payload = self._fit(payload)
        return ComplianceContext(analysis, payload)

    def _rules_text(self, any_violation_rule: bool) -> list[str]:
        p = self._settings.config.policy
        rules = [
            "Assess ONLY the candidate controls (use their control_id). Never add controls, frameworks or controls' framework ids.",
            f"Every assessment with status other than unknown/not_applicable (compliant included) cites at least "
            f"{p.min_evidence_for_assessment} evidence id AND at least {p.min_observed_for_adverse_status} OBSERVED "
            "item (AS, EV, PR, RS, SF). IF/MT/MF/TR are opinions. Never assume 'compliant' from missing evidence: use unknown.",
            "framework_assessments may only use a (framework, framework_control_id) pair listed in that control's "
            "framework_mappings; you may leave the list empty, the backend fills in the mapped controls.",
            "'violation' is allowed only for a control that has a matched_violation_rule and only with that rule_id; "
            "otherwise use potential_violation or potential_gap. Never call anything a legal or regulatory violation.",
            "reporting: use configured_requirement only with a rule_id from matched_reporting_rules; otherwise use "
            "internal_review_recommended or requires_manual_assessment. Never state deadlines, laws or regulations.",
            "Recommendations use only allowed.recommendation_types, and their rationale must ask for a REVIEW or assessment (start with e.g. \"Review...\" / \"Assess...\"), never instruct a change such as remove/disable/rotate.",
            "Do not restate the investigation. Say which controls and configured framework requirements the incident "
            "affects, why, and what is unknown. List missing information under unknowns (do not assume it).",
        ]
        if not any_violation_rule:
            rules.append("No violation rule matched: do not use status 'violation'.")
        return rules

    def _fit(self, payload: dict[str, Any]) -> dict[str, Any]:
        cap = self._settings.config.context.max_context_chars
        size = lambda: len(json.dumps(payload, default=str))  # noqa: E731
        while size() > cap and len(payload["evidence"]) > 8:
            payload["evidence"].pop()  # lowest-priority evidence first
        kept = {e["id"] for e in payload["evidence"]}
        payload["allowed"]["evidence_ids"] = [i for i in payload["allowed"]["evidence_ids"] if i in kept]
        return payload
