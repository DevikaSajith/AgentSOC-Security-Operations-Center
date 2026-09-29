"""rule_based_fallback: a deterministic triage used ONLY when the caller explicitly asks for
it and no valid LLM decision could be obtained. It is always stored and shown with
method=rule_based_fallback so it can never be mistaken for an LLM assessment."""

from app.agents.triage.config import TriageConfig
from app.agents.triage.context import TriageContext
from app.agents.triage.validation import SEVERITY_RANK
from app.domain.enums import Severity, TriageNextStep
from app.domain.incident import IncidentState
from app.domain.triage import RiskIndicator, TriageDecision


def monitor_signals(incident: IncidentState) -> list[str]:
    """The Monitor's group-level indicators (older incidents only stored the primary event's)."""
    normalized = incident.normalized_event
    return list(normalized.get("group_indicators") or normalized.get("indicators") or [])


def rule_based_decision(incident: IncidentState, context: TriageContext,
                        config: TriageConfig) -> TriageDecision:
    rules = config.fallback
    signals = monitor_signals(incident)
    severity = incident.severity
    escalated = severity == Severity.HIGH and any(s in signals for s in rules.escalate_to_critical_when)
    if escalated:
        severity = Severity.CRITICAL
    investigate = SEVERITY_RANK[severity] >= SEVERITY_RANK[rules.investigate_at_or_above]
    event_refs = [r for r, f in context.facts.items() if f.kind == "event"][:10]
    refs = event_refs or sorted(context.facts)[:1]
    return TriageDecision(
        severity=severity, priority=rules.priority_by_severity[severity],
        category=incident.category, confidence=rules.confidence,
        classification=f"{incident.category.value.upper()} incident (rule-based)",
        summary=(f"Rule-based fallback triage (no LLM decision): {len(event_refs)} correlated "
                 f"event(s) for {incident.principal_id}; Monitor signals: "
                 f"{', '.join(sorted(set(signals))) or 'none'}."),
        severity_rationale=("Escalated from high to critical: " + ", ".join(rules.escalate_to_critical_when)
                            if escalated else "Kept the Monitor's initial severity (rule-based)."),
        priority_rationale="Priority mapped from severity by the fallback rules.",
        risk_indicators=[RiskIndicator(indicator=f"monitor signal: {s}", evidence_refs=refs[:1])
                         for s in sorted(set(signals))[:8]]
        or [RiskIndicator(indicator="correlated activity opened by the Monitor", evidence_refs=refs[:1])],
        key_evidence=refs,
        investigation_required=investigate,
        investigation_reason=(f"Severity {severity.value} is at or above "
                              f"{rules.investigate_at_or_above.value}." if investigate
                              else "Severity below the investigation threshold."),
        recommended_next_step=TriageNextStep.INVESTIGATE if investigate else TriageNextStep.MONITOR,
    )
