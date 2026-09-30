"""Turns untrusted model text into an accepted ComplianceDecision, or explains why not; then the
backend FINALIZES it (final statuses, derived framework mappings, overall status, reporting).

    text -> JSON -> Pydantic -> evidence refs -> frameworks -> controls -> semantic -> policy
    accepted decision -> finalize(): downgrade over-claims (recorded), derive framework mappings,
                         derive overall status and reporting status (never invented by the model)
"""

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from app.agents.compliance.config import ComplianceSettings
from app.agents.compliance.context import ComplianceContext
from app.agents.structured import DecisionValidationError
from app.domain.compliance import (
    ADVERSE_STATUSES,
    STATUS_RANK,
    ComplianceDecision,
    ComplianceStatus,
    ControlAssessment,
    ControlGap,
    FrameworkAssessment,
    PotentialViolation,
    Recommendation,
    ReportingConsideration,
    ReportingStatus,
)
from app.llm.parsing import JSONExtractionError, extract_json_object

NEUTRAL = {ComplianceStatus.UNKNOWN, ComplianceStatus.NOT_APPLICABLE}


class ComplianceValidationError(DecisionValidationError):
    """code: invalid_json | schema_invalid | invalid_evidence_ref | invalid_framework |
    invalid_mapping | invalid_control | invalid_rule | semantic_invalid | policy_violation"""


def parse_decision(text: str) -> ComplianceDecision:
    try:
        data = extract_json_object(text)
    except JSONExtractionError as exc:
        raise ComplianceValidationError("invalid_json", [str(exc)]) from None
    try:
        return ComplianceDecision.model_validate(data)
    except ValidationError as exc:
        problems = [f"{'.'.join(map(str, e['loc'])) or 'object'}: {e['msg']}" for e in exc.errors()]
        raise ComplianceValidationError("schema_invalid", problems) from None


def _all_evidence_refs(d: ComplianceDecision) -> list[str]:
    return ([r for x in d.control_assessments for r in x.evidence_ids]
            + [r for x in d.framework_assessments for r in x.evidence_ids]
            + [r for x in d.control_gaps for r in x.evidence_ids]
            + [r for x in d.potential_violations for r in x.evidence_ids]
            + [r for x in d.reporting_considerations for r in x.evidence_ids]
            + [r for x in d.recommendations for r in x.evidence_ids])


def _text_fields(d: ComplianceDecision) -> list[str]:
    return ([d.summary] + [x.rationale for x in d.control_assessments]
            + [x.rationale for x in d.framework_assessments] + [x.description for x in d.control_gaps]
            + [x.statement for x in d.potential_violations] + [x.note for x in d.reporting_considerations]
            + [x.rationale for x in d.recommendations] + list(d.unknowns))


def check_evidence(d: ComplianceDecision, context: ComplianceContext) -> None:
    unknown = sorted(set(_all_evidence_refs(d)) - context.evidence_ids)
    if unknown:
        raise ComplianceValidationError(
            "invalid_evidence_ref", [f"unknown evidence ids {unknown}; allowed: {sorted(context.evidence_ids)}"])


def check_frameworks(d: ComplianceDecision, settings: ComplianceSettings) -> None:
    mapping = settings.mapping
    bad = sorted({x.framework for x in d.framework_assessments if x.framework not in mapping.frameworks})
    if bad:
        raise ComplianceValidationError(
            "invalid_framework", [f"frameworks {bad} are not configured; allowed: {sorted(mapping.frameworks)}"])
    problems = []
    for x in d.framework_assessments:
        if x.control_id in mapping.controls and mapping.framework_control(
                x.control_id, x.framework, x.framework_control_id) is None:
            problems.append(f"{x.framework} {x.framework_control_id} is not a configured mapping of control "
                            f"'{x.control_id}'")
    if problems:
        raise ComplianceValidationError("invalid_mapping", problems)


def check_controls(d: ComplianceDecision, context: ComplianceContext) -> None:
    allowed = set(context.analysis.candidates)
    used = ([x.control_id for x in d.control_assessments] + [x.control_id for x in d.framework_assessments]
            + [x.control_id for x in d.control_gaps] + [x.control_id for x in d.potential_violations]
            + [x.control_id for x in d.recommendations if x.control_id])
    bad = sorted(set(used) - allowed)
    if bad:
        raise ComplianceValidationError(
            "invalid_control", [f"control ids {bad} are not candidate controls for this incident; "
                                f"allowed: {sorted(allowed)}"])


def check_semantics(d: ComplianceDecision, context: ComplianceContext, settings: ComplianceSettings) -> None:
    policy, problems = settings.config.policy, []
    seen = [x.control_id for x in d.control_assessments]
    if len(set(seen)) != len(seen):
        problems.append("control_assessments lists the same control more than once")
    for x in d.control_assessments:
        if x.status not in NEUTRAL and len(set(x.evidence_ids)) < policy.min_evidence_for_assessment:
            problems.append(f"control {x.control_id} is '{x.status.value}' but cites no evidence; cite evidence or "
                            "use 'unknown'")
    for x in d.framework_assessments:
        if x.status not in NEUTRAL and not x.evidence_ids:
            problems.append(f"framework assessment {x.framework} {x.framework_control_id} cites no evidence")
    assessed = {x.control_id: x.status for x in d.control_assessments}
    for gap in d.control_gaps:
        if assessed.get(gap.control_id) not in ADVERSE_STATUSES:
            problems.append(f"control_gaps lists '{gap.control_id}' but its control assessment is not an adverse status")
    for v in d.potential_violations:
        if v.status not in (ComplianceStatus.POTENTIAL_VIOLATION, ComplianceStatus.VIOLATION):
            problems.append(f"potential_violations entry for '{v.control_id}' must have status potential_violation "
                            f"or violation, not '{v.status.value}'")
        if assessed.get(v.control_id) not in ADVERSE_STATUSES:
            problems.append(f"potential_violations lists '{v.control_id}' but its control assessment is not adverse")
    violation_ids = {r.id: r for r in settings.mapping.violation_rules}
    for v in d.potential_violations:
        if v.rule_id is not None and v.rule_id not in violation_ids:
            problems.append(f"rule_id '{v.rule_id}' is not a configured violation rule")
    reporting_ids = {r.id for r in settings.mapping.reporting_rules}
    matched_r = {m.rule_id for m in context.analysis.reporting_matches}
    for r in d.reporting_considerations:
        if r.rule_id is not None and r.rule_id not in reporting_ids:
            problems.append(f"reporting rule_id '{r.rule_id}' is not configured")
        if r.status == ReportingStatus.CONFIGURED_REQUIREMENT and (r.rule_id is None or r.rule_id not in matched_r):
            problems.append("reporting status 'configured_requirement' needs a rule_id from matched_reporting_rules; "
                            "use requires_manual_assessment for anything not configured")
    if problems:
        raise ComplianceValidationError("semantic_invalid", problems)


def check_policy(d: ComplianceDecision, context: ComplianceContext, settings: ComplianceSettings) -> None:
    policy, problems = settings.config.policy, []
    observed = context.analysis.observed_ids()
    for x in d.control_assessments:
        if x.status not in NEUTRAL and len(set(x.evidence_ids) & observed) < policy.min_observed_for_adverse_status:
            problems.append(f"control {x.control_id} is '{x.status.value}' but cites no OBSERVED evidence "
                            "(AS/EV/PR/RS/SF); IF/MT/MF/TR are opinions. Use 'unknown' when nothing observed "
                            "supports a status (compliance is never assumed from missing evidence)")
    allowed_types = set(policy.recommendation_types)
    for r in d.recommendations:
        if r.type not in allowed_types:
            problems.append(f"recommendation type '{r.type.value}' is not allowed")
    remediation = [re.compile(p, re.IGNORECASE) for p in policy.recommendation_forbidden_patterns]
    for r in d.recommendations:
        for pattern in remediation:
            hit = pattern.search(r.rationale)
            if hit:
                problems.append(f"recommendation '{r.type.value}' reads as a remediation step ('{hit.group(1)}...'); "
                                "recommendations must ask for a review or assessment, not instruct a change")
                break
    patterns = [re.compile(p, re.IGNORECASE) for p in policy.forbidden_text_patterns]
    for text in _text_fields(d):
        for pattern in patterns:
            hit = pattern.search(text)
            if hit:
                problems.append(f"text mentions '{hit.group(0)}': statutes, regulations and legal deadlines are not "
                                "configured and must not be stated")
                break
    if problems:
        raise ComplianceValidationError("policy_violation", problems[:12])


def validate_decision(text: str, context: ComplianceContext, settings: ComplianceSettings) -> ComplianceDecision:
    decision = parse_decision(text)
    check_evidence(decision, context)
    check_frameworks(decision, settings)
    check_controls(decision, context)
    check_semantics(decision, context, settings)
    check_policy(decision, context, settings)
    return decision


# ------------------------------------------------------------------------- finalization
@dataclass
class Finalized:
    controls: list[ControlAssessment]
    frameworks: list[FrameworkAssessment]
    gaps: list[ControlGap]
    violations: list[PotentialViolation]
    reporting: list[ReportingConsideration]
    reporting_status: ReportingStatus
    recommendations: list[Recommendation]
    overall_status: ComplianceStatus
    overall_note: str
    notes: list[str] = field(default_factory=list)


def _cap(status: ComplianceStatus, limit: ComplianceStatus) -> ComplianceStatus:
    """The lower-ranked of two statuses (neutral statuses pass through)."""
    if status in NEUTRAL or limit in NEUTRAL:
        return status
    return status if STATUS_RANK[status] <= STATUS_RANK[limit] else limit


def finalize(d: ComplianceDecision, context: ComplianceContext, settings: ComplianceSettings) -> Finalized:
    mapping, policy = settings.mapping, settings.config.policy
    analysis = context.analysis
    matched_by_control: dict[str, list[str]] = {}
    for m in analysis.violation_matches:
        matched_by_control.setdefault(m.control_id or "", []).append(m.rule_id)

    def final_status(status: ComplianceStatus, control_id: str, rule_id: str | None = None) -> tuple[ComplianceStatus, str | None]:
        if status != ComplianceStatus.VIOLATION or not policy.violation_requires_matched_rule:
            return status, None
        matched = matched_by_control.get(control_id, [])
        if matched and (rule_id is None or rule_id in matched):
            return status, None
        return (ComplianceStatus.POTENTIAL_VIOLATION,
                "downgraded to potential_violation: 'violation' requires a matched configured violation rule "
                f"for this control (matched: {matched or 'none'})")

    controls: dict[str, ControlAssessment] = {}
    for x in d.control_assessments:
        cand = analysis.candidates[x.control_id]
        status, note = final_status(x.status, x.control_id)
        controls[x.control_id] = ControlAssessment(
            control_id=x.control_id, control_name=cand.control.name, status=status, proposed_status=x.status,
            evidence_ids=list(dict.fromkeys(x.evidence_ids)), confidence=x.confidence, rationale=x.rationale, note=note)

    frameworks: dict[tuple[str, str, str], FrameworkAssessment] = {}
    for x in d.framework_assessments:
        ctrl = controls.get(x.control_id)
        status, note = final_status(x.status, x.control_id)
        if ctrl is not None and STATUS_RANK.get(status, -1) > STATUS_RANK.get(ctrl.status, 99):
            status, note = ctrl.status, f"capped to the control's final status '{ctrl.status.value}'"
        item = mapping.framework_control(x.control_id, x.framework, x.framework_control_id)
        assert item is not None
        frameworks[(x.framework, x.framework_control_id, x.control_id)] = FrameworkAssessment(
            framework=x.framework, framework_name=mapping.frameworks[x.framework].name,
            framework_control_id=item.id, framework_control_title=item.title, control_id=x.control_id,
            status=status, evidence_ids=list(dict.fromkeys(x.evidence_ids)), confidence=x.confidence,
            rationale=x.rationale, source="llm", note=note)
    for control_id, ctrl in controls.items():  # derive every configured mapping not covered by the model
        for framework, mapped in analysis.candidates[control_id].control.frameworks.items():
            for item in mapped:
                key = (framework, item.id, control_id)
                if key not in frameworks:
                    frameworks[key] = FrameworkAssessment(
                        framework=framework, framework_name=mapping.frameworks[framework].name,
                        framework_control_id=item.id, framework_control_title=item.title, control_id=control_id,
                        status=ctrl.status, evidence_ids=ctrl.evidence_ids, confidence=ctrl.confidence,
                        rationale=f"Inherited from control '{ctrl.control_name}' via the configured mapping.",
                        source="derived")

    gaps = [ControlGap(control_id=g.control_id, control_name=analysis.candidates[g.control_id].control.name,
                       description=g.description, evidence_ids=g.evidence_ids) for g in d.control_gaps]
    violations = []
    for v in d.potential_violations:
        status, note = final_status(v.status, v.control_id, v.rule_id)
        violations.append(PotentialViolation(
            control_id=v.control_id, control_name=analysis.candidates[v.control_id].control.name,
            rule_id=v.rule_id, status=status,
            proposed_status=v.status, statement=v.statement, evidence_ids=v.evidence_ids, note=note))

    reporting = [ReportingConsideration(status=r.status, rule_id=r.rule_id, note=r.note, source="llm",
                                        evidence_ids=r.evidence_ids,
                                        requirement=next((m.requirement for m in analysis.reporting_matches
                                                          if m.rule_id == r.rule_id), None))
                 for r in d.reporting_considerations]
    for m in analysis.reporting_matches:  # matched configured rules are backend-authoritative
        existing = next((r for r in reporting if r.rule_id == m.rule_id), None)
        if existing is None:
            reporting.append(ReportingConsideration(
                status=ReportingStatus.CONFIGURED_REQUIREMENT, rule_id=m.rule_id, requirement=m.requirement,
                note=m.description, source="configured_rule"))
        elif existing.status != ReportingStatus.CONFIGURED_REQUIREMENT:
            existing.status, existing.requirement = ReportingStatus.CONFIGURED_REQUIREMENT, m.requirement
            existing.note = f"{m.description} (status set by the backend from the matched configured rule)"
    if any(r.status == ReportingStatus.CONFIGURED_REQUIREMENT for r in reporting):
        reporting_status = ReportingStatus.CONFIGURED_REQUIREMENT
    elif any(r.status == ReportingStatus.INTERNAL_REVIEW_RECOMMENDED for r in reporting):
        reporting_status = ReportingStatus.INTERNAL_REVIEW_RECOMMENDED
    elif all(r.status == ReportingStatus.NOT_APPLICABLE for r in reporting):
        reporting_status = ReportingStatus.NOT_APPLICABLE
    else:
        reporting_status = ReportingStatus.REQUIRES_MANUAL_ASSESSMENT

    ranked = [c for c in controls.values() if c.status in STATUS_RANK]
    if ranked:
        worst = max(ranked, key=lambda c: STATUS_RANK[c.status])
        overall = worst.status
        note = f"Worst assessed control: {worst.control_name} = {worst.status.value}"
        if worst.status == ComplianceStatus.VIOLATION:
            note += f" (configured rule {', '.join(matched_by_control.get(worst.control_id, []))})"
        note += ". Derived by the backend from the control statuses."
    else:
        overall, note = ComplianceStatus.UNKNOWN, "No control could be assessed from the available evidence."
    recommendations = [Recommendation(type=r.type, control_id=r.control_id, rationale=r.rationale,
                                      evidence_ids=r.evidence_ids) for r in d.recommendations]
    return Finalized(list(controls.values()), list(frameworks.values()), gaps, violations, reporting,
                     reporting_status, recommendations, overall, note)


def debug_payload(f: Finalized) -> dict[str, Any]:  # used by audit
    return {"overall_status": f.overall_status.value,
            "controls": [f"{c.control_id}:{c.status.value}" for c in f.controls],
            "reporting_status": f.reporting_status.value,
            "frameworks": sorted({x.framework for x in f.frameworks})}
