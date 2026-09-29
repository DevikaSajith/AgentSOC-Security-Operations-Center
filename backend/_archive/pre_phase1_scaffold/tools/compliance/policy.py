"""
AgentSOC — Compliance Policy Engine

Deterministic policy rule evaluation. The LLM does NOT decide
whether actions are allowed — only these rules do.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import yaml

from backend.schemas.models import (
    AgentName,
    ComplianceResult,
    RiskLevel,
    ToolCall,
    ToolResult,
)

logger = logging.getLogger(__name__)


def _load_rules() -> List[Dict]:
    config_dir = os.environ.get(
        "CONFIG_DIR",
        os.path.join(os.path.dirname(__file__), "../../../config")
    )
    rules_path = os.path.join(config_dir, "compliance_rules.yaml")
    try:
        with open(rules_path, "r") as f:
            data = yaml.safe_load(f)
        return data.get("rules", [])
    except FileNotFoundError:
        logger.error("Compliance rules file not found at %s", rules_path)
        return []
    except Exception as e:
        logger.error("Error loading compliance rules: %s", e)
        return []


_RULES: Optional[List[Dict]] = None


def get_rules() -> List[Dict]:
    global _RULES
    if _RULES is None:
        _RULES = _load_rules()
    return _RULES


# ============================================================
# Action → Condition Mapping
# Maps proposed actions to the conditions that activate a rule
# ============================================================

ACTION_CONDITION_MAP: Dict[str, str] = {
    "disable_access_key": "compromised_access_key",
    "delete_access_key": "suspicious_new_access_key",
    "detach_policy": "unauthorized_policy_attachment",
    "revoke_sessions": "compromised_identity",
    "make_bucket_private": "public_sensitive_bucket",
    "apply_public_access_block": "bucket_public_access_block_missing",
    "isolate_instance": "compromised_instance",
    "apply_quarantine_sg": "suspected_c2_beacon",
    "force_password_reset": "credential_misuse_confirmed",
}

# Additional condition mappings for specific scenarios
SCENARIO_CONDITION_OVERRIDES: Dict[str, str] = {
    "impossible_travel": "impossible_travel_detected",
}


def evaluate_compliance(
    proposed_action: str,
    target: str,
    incident_type: str,
    severity: str,
    context: Dict[str, Any],
    agent: AgentName = AgentName.COMPLIANCE,
    incident_id: Optional[str] = None,
) -> tuple[ToolCall, ToolResult, ComplianceResult]:
    """
    Evaluate whether a proposed remediation action is permitted by policy.
    
    Returns:
        (ToolCall, ToolResult, ComplianceResult)
    """
    call = ToolCall(
        tool_name="evaluate_compliance",
        agent=agent,
        incident_id=incident_id,
        arguments={
            "proposed_action": proposed_action,
            "target": target,
            "incident_type": incident_type,
            "severity": severity,
        },
    )

    rules = get_rules()

    # Determine the condition for this action
    condition = ACTION_CONDITION_MAP.get(proposed_action)

    # Check for scenario-specific overrides
    if context.get("impossible_travel") and proposed_action == "disable_access_key":
        condition = "impossible_travel_detected"

    # Find matching rule
    matching_rule = None
    for rule in rules:
        if rule.get("action") == proposed_action:
            if condition and rule.get("condition") == condition:
                matching_rule = rule
                break
            elif not condition:
                matching_rule = rule
                break

    # If no rule matches, default to BLOCKED (fail-safe)
    if not matching_rule:
        result = ComplianceResult(
            incident_id=incident_id or "",
            allowed=False,
            risk=RiskLevel.HIGH,
            approval_required=True,
            policy_id="NO-MATCHING-RULE",
            reason=f"No compliance rule found for action '{proposed_action}'. Defaulting to deny.",
            proposed_action=proposed_action,
            proposed_action_target=target,
        )
        tool_result = ToolResult(
            tool_id=call.tool_id,
            tool_name=call.tool_name,
            success=True,
            data=result.model_dump(),
        )
        return call, tool_result, result

    # Parse risk level
    risk_str = matching_rule.get("risk", "MEDIUM").upper()
    risk = RiskLevel(risk_str.lower())

    # Determine approval requirement
    # Rule's setting is the base; environment config can add more strictness
    approval_required = matching_rule.get("approval_required", True)

    # Additional env-level override: always require approval for CRITICAL
    if severity == "critical" and not approval_required:
        require_for_critical = os.environ.get("REQUIRE_APPROVAL_FOR_CRITICAL", "true").lower() == "true"
        if require_for_critical:
            approval_required = True

    result = ComplianceResult(
        incident_id=incident_id or "",
        allowed=True,
        risk=risk,
        approval_required=approval_required,
        policy_id=matching_rule["id"],
        reason=f"Action is permitted under policy {matching_rule['id']}. {matching_rule.get('notes', '')}".strip(),
        proposed_action=proposed_action,
        proposed_action_target=target,
    )

    tool_result = ToolResult(
        tool_id=call.tool_id,
        tool_name=call.tool_name,
        success=True,
        data=result.model_dump(),
    )

    return call, tool_result, result


def get_rule_by_id(rule_id: str) -> Optional[Dict]:
    return next((r for r in get_rules() if r["id"] == rule_id), None)


def list_rules() -> List[Dict]:
    return get_rules()
