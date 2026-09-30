"""Turns untrusted model text into an accepted TriageDecision, or explains why not.

    text -> JSON extraction -> Pydantic (TriageDecision) -> semantic checks -> policy checks

Nothing here modifies anything; the agent only updates the incident after this passes.
"""

from pydantic import ValidationError

from app.agents.structured import DecisionValidationError
from app.agents.triage.config import TriageConfig
from app.domain.enums import Priority, Severity, TriageNextStep
from app.domain.triage import TriageDecision
from app.llm.parsing import JSONExtractionError, extract_json_object

SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3,
                 Severity.CRITICAL: 4}
PRIORITY_RANK = {Priority.P1: 1, Priority.P2: 2, Priority.P3: 3, Priority.P4: 4}
INVESTIGATION_STEPS = {TriageNextStep.INVESTIGATE, TriageNextStep.ESCALATE}


class TriageValidationError(DecisionValidationError):
    """code: invalid_json | schema_invalid | semantic_invalid | policy_violation"""


def parse_decision(text: str) -> TriageDecision:
    try:
        data = extract_json_object(text)
    except JSONExtractionError as exc:
        raise TriageValidationError("invalid_json", [str(exc)]) from None
    try:
        return TriageDecision.model_validate(data)
    except ValidationError as exc:
        problems = [f"{'.'.join(map(str, e['loc'])) or 'object'}: {e['msg']}" for e in exc.errors()]
        raise TriageValidationError("schema_invalid", problems) from None


def check_semantics(decision: TriageDecision, allowed_refs: set[str]) -> None:
    problems = []
    cited = list(decision.key_evidence) + [r for i in decision.risk_indicators for r in i.evidence_refs]
    unknown = sorted({r for r in cited if r not in allowed_refs})
    if unknown:
        problems.append(f"unknown evidence refs {unknown}; allowed: {sorted(allowed_refs)}")
    if len(set(decision.key_evidence)) != len(decision.key_evidence):
        problems.append("key_evidence contains duplicate refs")
    step, required = decision.recommended_next_step, decision.investigation_required
    if required and step not in INVESTIGATION_STEPS:
        problems.append(f"investigation_required is true but recommended_next_step is '{step.value}'")
    if not required and step in INVESTIGATION_STEPS:
        problems.append(f"investigation_required is false but recommended_next_step is '{step.value}'")
    if problems:
        raise TriageValidationError("semantic_invalid", problems)


def check_policy(decision: TriageDecision, config: TriageConfig) -> None:
    rules, problems = config.policy, []
    severity = SEVERITY_RANK[decision.severity]
    if decision.recommended_next_step == TriageNextStep.CLOSE:
        if severity >= SEVERITY_RANK[rules.close_forbidden_at_or_above]:
            problems.append(f"cannot recommend 'close' at severity {decision.severity.value}")
        if decision.confidence < rules.min_confidence_to_close:
            problems.append(f"'close' needs confidence >= {rules.min_confidence_to_close}")
    if decision.priority == Priority.P1 and severity < SEVERITY_RANK[rules.p1_requires_severity_at_least]:
        problems.append(f"P1 requires severity >= {rules.p1_requires_severity_at_least.value}")
    if (decision.severity == Severity.CRITICAL
            and PRIORITY_RANK[decision.priority] > PRIORITY_RANK[rules.critical_requires_priority_at_most]):
        problems.append(f"critical severity requires priority {rules.critical_requires_priority_at_most.value} or higher")
    if problems:
        raise TriageValidationError("policy_violation", problems)


def check_ml_copy(decision: TriageDecision, ml_probability: float | None) -> None:
    """The ML probability is decision support; a model that just echoes it as its own confidence is not
    assessing anything (the same failure was seen with the Monitor's confidence)."""
    if ml_probability is not None and round(decision.confidence, 2) == ml_probability:
        raise TriageValidationError("policy_violation", [
            f"confidence {decision.confidence} equals the ML threat probability; give your own confidence in this "
            "assessment based on how complete and consistent the evidence is"])


def validate_decision(text: str, allowed_refs: set[str], config: TriageConfig,
                      ml_probability: float | None = None) -> TriageDecision:
    decision = parse_decision(text)
    check_semantics(decision, allowed_refs)
    check_policy(decision, config)
    check_ml_copy(decision, ml_probability)
    return decision
