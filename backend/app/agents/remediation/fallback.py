"""Deterministic rule-based remediation planner (used only when the request allows it and no valid LLM
decision was obtained). It produces a RemediationDecision that goes through the SAME validation, policy,
approval and kill-switch path as the model's - it bypasses nothing."""

from app.agents.remediation.analysis import Candidate
from app.agents.remediation.config import RemediationPolicy
from app.agents.remediation.context import RemediationContext
from app.domain.remediation import RemediationAction, RemediationDecision


def rule_based_decision(context: RemediationContext, policy: RemediationPolicy) -> RemediationDecision:
    order = {name: i for i, name in enumerate(policy.policy.fallback_priority)}
    ranked = sorted(context.analysis.candidates,
                    key=lambda c: (order.get(c.action.value, len(order)), c.candidate_id))
    chosen: Candidate | None = ranked[0] if ranked else None
    if chosen is None:
        return RemediationDecision(
            action=RemediationAction.NO_ACTION, target=None,
            reason="No configured remediation action is applicable to the current cloud state.",
            evidence_ids=[], expected_effect="No change to the simulated cloud.", risk_level="info",
            rollback_available=False, rollback_description="Nothing is changed, so there is nothing to roll back.",
            requires_approval=False, confidence=policy.policy.fallback_confidence,
            unknowns=["Selected by a deterministic rule, not by model reasoning."])
    action_policy = policy.actions[chosen.action.value]
    return RemediationDecision(
        action=chosen.action, target=chosen.target,
        reason=f"Deterministic rule: {chosen.description}; " + "; ".join(chosen.reasons)[:250],
        evidence_ids=chosen.evidence_ids[:12], expected_effect=chosen.description + ".",
        risk_level=action_policy.risk, rollback_available=action_policy.rollback_available,
        rollback_description=action_policy.rollback_description[:300],
        requires_approval=True, confidence=policy.policy.fallback_confidence,
        unknowns=["Selected by a deterministic rule, not by model reasoning; the least disruptive "
                  "applicable action was chosen from the configured priority order."])
