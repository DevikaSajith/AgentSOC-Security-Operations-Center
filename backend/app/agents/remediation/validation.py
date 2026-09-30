"""Turns untrusted model text into an accepted RemediationDecision, or explains why not; then the backend
FINALIZES it into a RemediationPlan (exact tool arguments, policy risk, approval, rollback).

    text -> JSON -> Pydantic (unknown fields rejected) -> action -> target -> evidence -> policy
    accepted decision -> finalize(): the plan's action/target/arguments come from the backend's candidate,
                         risk / approval / rollback come from config/remediation_policy.yaml
                         (model values that differ are replaced and recorded, never silently kept)

Invalid proposals never reach an approval request, let alone execution.
"""

import re
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from app.agents.remediation.analysis import Candidate
from app.agents.remediation.config import RemediationPolicy
from app.agents.remediation.context import RemediationContext
from app.agents.structured import DecisionValidationError
from app.domain.enums import Severity
from app.domain.remediation import PolicyNote, RemediationAction, RemediationDecision, RemediationPlan
from app.llm.parsing import JSONExtractionError, extract_json_object
from app.services.approvals import proposal_hash


class RemediationValidationError(DecisionValidationError):
    """code: invalid_json | schema_invalid | invalid_action | invalid_target | invalid_evidence_ref |
    policy_violation"""


def parse_decision(text: str) -> RemediationDecision:
    try:
        data = extract_json_object(text)
    except JSONExtractionError as exc:
        raise RemediationValidationError("invalid_json", [str(exc)]) from None
    try:
        return RemediationDecision.model_validate(data)
    except ValidationError as exc:
        problems = [f"{'.'.join(map(str, e['loc'])) or 'object'}: {e['msg']}" for e in exc.errors()]
        raise RemediationValidationError("schema_invalid", problems) from None


def check_action(d: RemediationDecision, context: RemediationContext) -> None:
    allowed = {c.action for c in context.analysis.candidates}
    if d.action != RemediationAction.NO_ACTION and d.action not in allowed:
        raise RemediationValidationError("invalid_action", [
            f"action '{d.action.value}' is not one of the allowed candidate actions "
            f"{sorted(a.value for a in allowed) or 'none'} (or no_action)"])


def check_target(d: RemediationDecision, context: RemediationContext) -> None:
    if d.action == RemediationAction.NO_ACTION:
        if d.target not in (None, "", "none"):
            raise RemediationValidationError("invalid_target", ["no_action must have target null"])
        return
    if context.analysis.find(d.action, d.target) is None:
        targets = sorted({c.target for c in context.analysis.candidates if c.action == d.action})
        raise RemediationValidationError("invalid_target", [
            f"target '{d.target}' is not a valid target for {d.action.value}; valid targets: {targets}"])


def check_evidence(d: RemediationDecision, context: RemediationContext) -> None:
    unknown = sorted(set(d.evidence_ids) - context.evidence_ids)
    if unknown:
        raise RemediationValidationError(
            "invalid_evidence_ref", [f"unknown evidence ids {unknown}; allowed: {sorted(context.evidence_ids)}"])


def check_policy(d: RemediationDecision, context: RemediationContext, policy: RemediationPolicy) -> None:
    rules, problems = policy.policy, []
    if d.action != RemediationAction.NO_ACTION:
        cited = set(d.evidence_ids)
        if len(cited) < rules.min_evidence_for_action:
            problems.append(f"an action must cite at least {rules.min_evidence_for_action} evidence id")
        if len(cited & context.analysis.observed_ids()) < rules.min_observed_for_action:
            problems.append("an action must cite at least "
                            f"{rules.min_observed_for_action} OBSERVED evidence id (AS/CS/EV/PR/RS/SF); "
                            "IF/MT/MF/TR are opinions")
        if not policy.actions[d.action.value].enabled:
            problems.append(f"action '{d.action.value}' is disabled by policy")
    patterns = [re.compile(p) for p in rules.forbidden_text_patterns]
    for text in [d.reason, d.expected_effect, d.rollback_description, *d.unknowns]:
        for pattern in patterns:
            hit = pattern.search(text)
            if hit:
                problems.append(f"text contains '{hit.group(0).strip()}': commands, code, CLI, SQL and URLs are not allowed")
                break
    if problems:
        raise RemediationValidationError("policy_violation", problems[:12])


def validate_decision(text: str, context: RemediationContext, policy: RemediationPolicy) -> RemediationDecision:
    decision = parse_decision(text)
    check_action(decision, context)
    check_target(decision, context)
    check_evidence(decision, context)
    check_policy(decision, context, policy)
    return decision


# ------------------------------------------------------------------------- finalization
def finalize(d: RemediationDecision, context: RemediationContext, policy: RemediationPolicy,
             incident_id: str) -> RemediationPlan:
    """The plan the human sees and the backend may later execute. Tool arguments are NEVER taken from the
    model: they come from the backend's candidate."""
    plan_id = f"PLAN-{uuid4().hex[:8].upper()}"
    evidence_ids = list(dict.fromkeys(d.evidence_ids))
    excluded = list(context.analysis.excluded) + list(context.analysis.already_remediated)
    if d.action == RemediationAction.NO_ACTION:
        return RemediationPlan(
            plan_id=plan_id, action=RemediationAction.NO_ACTION, reason=d.reason, evidence_ids=evidence_ids,
            expected_effect=d.expected_effect, risk=Severity.INFO, proposed_risk=d.risk_level,
            requires_approval=False, rollback_available=False,
            rollback_description="Nothing is changed, so there is nothing to roll back.", excluded_actions=excluded)
    candidate: Candidate | None = context.analysis.find(d.action, d.target)
    assert candidate is not None
    action_policy = policy.actions[d.action.value]
    notes: list[PolicyNote] = []
    if d.risk_level != action_policy.risk:
        notes.append(PolicyNote(field="risk", proposed=d.risk_level.value, final=action_policy.risk.value,
                                note="risk is set by config/remediation_policy.yaml, not by the model"))
    if not d.requires_approval:
        notes.append(PolicyNote(field="requires_approval", proposed="false", final="true",
                                note="every remediation action requires human approval"))
    if d.rollback_available != action_policy.rollback_available:
        notes.append(PolicyNote(
            field="rollback_available", proposed=str(d.rollback_available).lower(),
            final=str(action_policy.rollback_available).lower(),
            note="rollback availability is set by policy; no rollback tool is registered"))
    return RemediationPlan(
        plan_id=plan_id, action=d.action, tool_name=d.action.value, target=candidate.target,
        arguments=dict(candidate.arguments), reason=d.reason, evidence_ids=evidence_ids,
        expected_effect=d.expected_effect, risk=action_policy.risk, proposed_risk=d.risk_level,
        requires_approval=True, rollback_available=action_policy.rollback_available,
        rollback_description=action_policy.rollback_description, policy_notes=notes,
        state_fingerprint=candidate.fingerprint,
        proposal_hash=proposal_hash(incident_id, d.action.value, candidate.target, candidate.arguments),
        excluded_actions=excluded)


def debug_payload(plan: RemediationPlan) -> dict[str, Any]:
    """Audit-safe view of a plan: no prompts, no raw model output, no credentials."""
    return {"plan_id": plan.plan_id, "action": plan.action.value, "target": plan.target,
            "risk": plan.risk.value, "proposed_risk": plan.proposed_risk.value,
            "evidence_ids": plan.evidence_ids, "requires_approval": plan.requires_approval,
            "policy_notes": [n.model_dump() for n in plan.policy_notes]}
