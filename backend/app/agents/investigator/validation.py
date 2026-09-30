"""Turns untrusted model text into an accepted InvestigationDecision, or explains why not.

    text -> JSON extraction -> Pydantic -> semantic -> evidence references -> MITRE -> policy
"""

from pathlib import Path

from pydantic import ValidationError

from app.agents.investigator.config import InvestigatorConfig
from app.agents.investigator.context import InvestigationContext
from app.agents.structured import DecisionValidationError
from app.domain.investigation import (
    AttackStage,
    Certainty,
    Finding,
    InvestigationDecision,
    InvestigationNextStep,
)
from app.knowledge.mitre import load_techniques
from app.llm.parsing import JSONExtractionError, extract_json_object


class InvestigationValidationError(DecisionValidationError):
    """code: invalid_json | schema_invalid | semantic_invalid | invalid_evidence_ref |
    invalid_mitre | policy_violation"""


def parse_decision(text: str) -> InvestigationDecision:
    try:
        data = extract_json_object(text)
    except JSONExtractionError as exc:
        raise InvestigationValidationError("invalid_json", [str(exc)]) from None
    try:
        return InvestigationDecision.model_validate(data)
    except ValidationError as exc:
        problems = [f"{'.'.join(map(str, e['loc'])) or 'object'}: {e['msg']}" for e in exc.errors()]
        raise InvestigationValidationError("schema_invalid", problems) from None


def check_semantics(d: InvestigationDecision) -> None:
    problems = []
    notes = [n.evidence_id for n in d.timeline_notes]
    if len(set(notes)) != len(notes):
        problems.append("timeline_notes annotate the same evidence id more than once")
    for n, stage in enumerate(d.attack_sequence, 1):
        if stage.certainty == Certainty.UNSUPPORTED and stage.evidence_ids:
            problems.append(f"attack_sequence[{n}] is 'unsupported' but cites evidence")
        if stage.certainty != Certainty.UNSUPPORTED and not stage.evidence_ids:
            problems.append(f"attack_sequence[{n}] ({stage.stage.value}) claims '{stage.certainty.value}' "
                            "without citing evidence; cite evidence or mark it 'unsupported'")
    for n, finding in enumerate(d.findings, 1):
        if finding.certainty == Certainty.UNSUPPORTED:
            problems.append(f"findings[{n}] is 'unsupported'; a finding must be supported by evidence")
    ids = [m.technique_id for m in d.mitre_techniques]
    if len(set(ids)) != len(ids):
        problems.append("mitre_techniques lists the same technique more than once")
    if problems:
        raise InvestigationValidationError("semantic_invalid", problems)


def check_references(d: InvestigationDecision, context: InvestigationContext) -> None:
    allowed, timeline = context.evidence_ids, context.timeline_ids
    problems = []
    bad_notes = sorted({n.evidence_id for n in d.timeline_notes} - timeline)
    if bad_notes:
        problems.append(f"timeline_notes cite {bad_notes}, which are not timeline events; "
                        f"allowed: {sorted(timeline)}")
    cited = ([r for s in d.attack_sequence for r in s.evidence_ids]
             + [r for f in d.findings for r in f.evidence_ids]
             + [r for m in d.mitre_techniques for r in m.evidence_ids])
    unknown = sorted(set(cited) - allowed)
    if unknown:
        problems.append(f"unknown evidence ids {unknown}; allowed: {sorted(allowed)}")
    if problems:
        raise InvestigationValidationError("invalid_evidence_ref", problems)


def check_mitre(d: InvestigationDecision, config_dir: Path) -> None:
    known = load_techniques(config_dir)
    unknown = [m.technique_id for m in d.mitre_techniques if m.technique_id not in known]
    if unknown:
        raise InvestigationValidationError(
            "invalid_mitre", [f"technique ids {unknown} are not in the project's MITRE mapping; "
                              f"allowed: {sorted(known)}"])


def classify(d: InvestigationDecision, context: InvestigationContext,
             config: InvestigatorConfig) -> tuple[list[Finding], list[AttackStage]]:
    """Backend classification rules: the model PROPOSES certainty/confidence; the backend
    decides the final values. Over-claims are downgraded and the change is recorded."""
    rules = config.policy
    observed = context.catalog.observed_ids()

    def final_certainty(proposed: Certainty, evidence: list[str], critical: bool) -> tuple[Certainty, list[str]]:
        notes = []
        if proposed != Certainty.CONFIRMED:
            return proposed, notes
        if len([e for e in evidence if e in observed]) < rules.confirmed_min_observed_evidence:
            notes.append("downgraded to suspected: 'confirmed' needs observed evidence (EV/PR/RS/SF); "
                         "Monitor/Triage opinions cannot confirm")
        elif critical and len(set(evidence)) < rules.critical_confirmed_min_evidence:
            notes.append(f"downgraded to suspected: a confirmed critical claim needs at least "
                         f"{rules.critical_confirmed_min_evidence} evidence items")
        return (Certainty.SUSPECTED if notes else proposed), notes

    findings = []
    for n, f in enumerate(d.findings, 1):
        certainty, notes = final_certainty(f.certainty, f.evidence_ids, f.type in rules.critical_finding_types)
        confidence = f.confidence
        if confidence >= rules.high_confidence_threshold and \
                len(set(f.evidence_ids)) < rules.high_confidence_min_evidence:
            confidence = round(rules.high_confidence_threshold - 0.01, 2)
            notes.append(f"confidence capped at {confidence}: >= {rules.high_confidence_threshold} "
                         f"needs {rules.high_confidence_min_evidence} evidence items")
        findings.append(Finding(finding_id=f"F{n}", type=f.type, statement=f.statement,
                                evidence_ids=f.evidence_ids, confidence=confidence, classification=certainty,
                                proposed_confidence=f.confidence, proposed_certainty=f.certainty,
                                classification_note="; ".join(notes) or None))
    stages = []
    for n, s in enumerate(d.attack_sequence, 1):
        certainty, notes = final_certainty(s.certainty, s.evidence_ids, s.stage in rules.critical_finding_types)
        stages.append(AttackStage(order=n, stage=s.stage, description=s.description,
                                  evidence_ids=s.evidence_ids, certainty=certainty,
                                  proposed_certainty=s.certainty,
                                  classification_note="; ".join(notes) or None))
    return findings, stages


def check_policy(d: InvestigationDecision, context: InvestigationContext, config: InvestigatorConfig) -> None:
    """Hard rules: a violation rejects the answer."""
    rules, problems = config.policy, []
    for m in d.mitre_techniques:
        if len(set(m.evidence_ids)) < rules.mitre_min_evidence:
            problems.append(f"{m.technique_id} needs at least {rules.mitre_min_evidence} evidence item(s)")
    if rules.summary_must_name_entity:
        names = {e.value.split("/", 1)[-1].lower() for e in context.entities
                 if e.type not in ("account", "region", "access_key")}
        if names and not any(name and name in d.summary.lower() for name in names):
            problems.append("summary must name at least one concrete principal, IP or resource from "
                            f"the evidence (e.g. {sorted(names)[:4]})")
    findings, _ = classify(d, context, config)
    if rules.close_forbidden_with_confirmed_findings and d.recommended_next_step == InvestigationNextStep.CLOSE:
        if any(f.classification == Certainty.CONFIRMED for f in findings):
            problems.append("cannot recommend 'close' while findings are confirmed")
    critical = [f for f in findings if f.type in rules.critical_finding_types
                and f.classification in (Certainty.CONFIRMED, Certainty.SUSPECTED)]
    allowed_steps = rules.critical_findings_require_next_step
    if critical and allowed_steps and d.recommended_next_step not in allowed_steps:
        problems.append(f"findings {[f.finding_id for f in critical]} ({', '.join(sorted({f.type.value for f in critical}))}) "
                        f"require recommended_next_step in {[s.value for s in allowed_steps]}, "
                        f"not '{d.recommended_next_step.value}'")
    if problems:
        raise InvestigationValidationError("policy_violation", problems)


def validate_decision(text: str, context: InvestigationContext, config: InvestigatorConfig,
                      config_dir: Path) -> InvestigationDecision:
    decision = parse_decision(text)
    check_semantics(decision)
    check_references(decision, context)
    check_mitre(decision, config_dir)
    check_policy(decision, context, config)
    return decision
