"""rule_based_fallback: a deterministic investigation used ONLY when the request sets
allow_rule_based_fallback=true and no valid LLM decision was obtained. It is labelled
method=rule_based_fallback everywhere and never claims 'confirmed' findings."""

from app.agents.investigator.config import InvestigatorConfig
from app.agents.investigator.context import InvestigationContext
from app.domain.investigation import (
    AttackStageProposal,
    Certainty,
    FindingProposal,
    InvestigationDecision,
    InvestigationNextStep,
    MitreProposal,
    TimelineNote,
)


def rule_based_decision(context: InvestigationContext, config: InvestigatorConfig) -> InvestigationDecision:
    rules = config.fallback
    events = context.catalog.events
    stages: dict[str, list[str]] = {}
    notes = []
    for e in events:
        stage = config.stage_by_event_type.get(e.event_type)
        notes.append(TimelineNote(evidence_id=e.evidence_id,
                                  significance=f"{e.event_type}" + (f" (usually {stage.value})" if stage else "")))
        if stage:
            stages.setdefault(stage.value, []).append(e.evidence_id)
    principals = sorted({e.principal for e in events if e.principal != "unknown"})
    ips = sorted({e.source_ip for e in events if e.source_ip != "0.0.0.0"})
    who = ", ".join(principals) or "an unknown principal"
    sequence = [AttackStageProposal(stage=s, description=f"Rule-based: event types usually indicating {s}",
                                    evidence_ids=ids[:10], certainty=Certainty.SUSPECTED)
                for s, ids in stages.items()] or [
        AttackStageProposal(stage="other", description="No stage mapping for these event types",
                            evidence_ids=[], certainty=Certainty.UNSUPPORTED)]
    findings = [FindingProposal(type=s, statement=f"Events {', '.join(ids[:5])} by {who} match the "
                                                  f"'{s}' pattern (rule-based, not analysed by an LLM).",
                                evidence_ids=ids[:10], confidence=rules.finding_confidence,
                                certainty=Certainty.SUSPECTED)
                for s, ids in stages.items()] or [
        FindingProposal(type="other", statement=f"{len(events)} correlated event(s) by {who}.",
                        evidence_ids=[e.evidence_id for e in events][:10] or list(context.evidence_ids)[:1],
                        confidence=rules.finding_confidence, certainty=Certainty.POSSIBLE)]
    mitre = [MitreProposal(technique_id=c["technique_id"], confidence=rules.mitre_confidence,
                           evidence_ids=c["matched_evidence_ids"][:10],
                           rationale="Rule-based: cited events are relevant events for this technique.")
             for c in context.mitre_candidates if "." in c["technique_id"]
             or not any(o["technique_id"].startswith(c["technique_id"] + ".") for o in context.mitre_candidates)]
    critical = {t.value for t in config.policy.critical_finding_types}
    return InvestigationDecision(
        summary=(f"Rule-based fallback (no LLM analysis): {len(events)} event(s) by {who} from "
                 f"{', '.join(ips) or 'unknown IPs'}; stage patterns: {', '.join(stages) or 'none'}."),
        confidence=rules.confidence, timeline_notes=notes[:40] or [TimelineNote(
            evidence_id=next(iter(context.timeline_ids)), significance="event")],
        attack_sequence=sequence[:8], findings=findings[:10], mitre_techniques=mitre[:8],
        root_cause_hypothesis=(f"Hypothesis (rule-based): the activity of {who} may reflect misuse of that "
                               "identity; the evidence does not show how access was obtained."),
        unknowns=(context.catalog.limitations[:3] or ["How the principal's access was obtained."]),
        alternative_hypotheses=["The activity could be legitimate administration by the principal."],
        recommended_next_step=(InvestigationNextStep.COMPLIANCE_REVIEW if critical & set(stages)
                               else InvestigationNextStep.MONITOR),
    )
