"""rule_based_fallback: a deterministic compliance assessment used ONLY when the request sets
allow_rule_based_fallback=true and no valid LLM decision was obtained. It is labelled
method=rule_based_fallback everywhere, never claims a violation on its own, and uses only what the
configuration and the incident's evidence directly support."""

from app.agents.compliance.config import ComplianceSettings
from app.agents.compliance.context import ComplianceContext
from app.domain.compliance import (
    ComplianceDecision,
    ComplianceStatus,
    ControlAssessmentProposal,
    GapProposal,
    RecommendationProposal,
    RecommendationType,
    ReportingProposal,
    ReportingStatus,
    ViolationProposal,
)

RECOMMENDATION_BY_CONTROL = {
    "least_privilege": RecommendationType.REVIEW_IAM_PRIVILEGES,
    "access_control": RecommendationType.REVIEW_ACCESS_CONTROL_CONFIGURATION,
    "credential_management": RecommendationType.REVIEW_CREDENTIAL_ROTATION,
    "data_protection": RecommendationType.REVIEW_DATA_PROTECTION_CONTROLS,
    "network_security": RecommendationType.REVIEW_NETWORK_CONTROLS,
    "logging_monitoring": RecommendationType.VALIDATE_LOGGING_COVERAGE,
    "incident_response": RecommendationType.PERFORM_COMPLIANCE_TEAM_ASSESSMENT,
}


def rule_based_decision(context: ComplianceContext, settings: ComplianceSettings) -> ComplianceDecision:
    rules = settings.config.fallback
    analysis = context.analysis
    matched = {m.control_id: m for m in analysis.violation_matches}
    controls, gaps, violations, recommendations = [], [], [], []
    for control_id, cand in analysis.candidates.items():
        evidence = [e for e in cand.matched_evidence_ids if e in context.evidence_ids][:10]
        if control_id in matched:
            rule = matched[control_id]
            evidence = list(dict.fromkeys(rule.evidence_ids + evidence))[:10]
            status = ComplianceStatus.POTENTIAL_VIOLATION
            text = f"Rule-based: configured rule {rule.rule_id} matched: {rule.description}"
            violations.append(ViolationProposal(control_id=control_id, rule_id=rule.rule_id, status=status,
                                                statement=text, evidence_ids=evidence[:10]))
        elif evidence:
            status = ComplianceStatus.POTENTIAL_GAP
            text = "Rule-based: incident events engaged this control; its effectiveness could not be confirmed."
        else:
            status, text = ComplianceStatus.UNKNOWN, "Rule-based: no evidence engages this control directly."
        if status in (ComplianceStatus.POTENTIAL_GAP, ComplianceStatus.POTENTIAL_VIOLATION):
            gaps.append(GapProposal(control_id=control_id, description=text, evidence_ids=evidence))
        controls.append(ControlAssessmentProposal(control_id=control_id, status=status, evidence_ids=evidence,
                                                  confidence=rules.control_confidence, rationale=text))
        if status != ComplianceStatus.UNKNOWN and control_id in RECOMMENDATION_BY_CONTROL:
            recommendations.append(RecommendationProposal(
                type=RECOMMENDATION_BY_CONTROL[control_id], control_id=control_id,
                rationale=f"Review the {cand.control.name} control given the incident evidence.",
                evidence_ids=evidence[:3]))
    if not recommendations:
        recommendations.append(RecommendationProposal(
            type=RecommendationType.PERFORM_COMPLIANCE_TEAM_ASSESSMENT, control_id=None,
            rationale="No control could be assessed automatically; a manual assessment is needed.",
            evidence_ids=[]))
    return ComplianceDecision(
        summary=(f"Rule-based fallback (no LLM analysis): {len(analysis.candidates)} candidate control(s) "
                 f"engaged; {sum(1 for c in controls if c.status != ComplianceStatus.UNKNOWN)} assessed from "
                 "configured triggers."),
        confidence=rules.confidence, control_assessments=controls[:8], framework_assessments=[],
        control_gaps=gaps[:8], potential_violations=violations[:8],
        reporting_considerations=[ReportingProposal(
            status=ReportingStatus.REQUIRES_MANUAL_ASSESSMENT, rule_id=None, evidence_ids=[],
            note="Reporting obligations beyond the configured internal rules require manual assessment.")],
        recommendations=recommendations[:8],
        unknowns=["Not analysed by an LLM; interpretation of impact is limited to configured triggers."])
