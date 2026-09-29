"""
AgentSOC — Deterministic Remediation Simulator Tools

These tools modify the SIMULATED cloud state (SQLite).
They NEVER call real AWS APIs.
Each tool:
  1. Reads the current simulated state (before_state)
  2. Validates the action is safe to perform
  3. Applies the change to simulated state
  4. Returns before/after state for the audit trail
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from backend.schemas.models import (
    AgentName,
    RemediationStatus,
    ToolCall,
    ToolResult,
    VerificationStatus,
)

logger = logging.getLogger(__name__)


def _get_simulated_state(resource_id: str, db_session) -> Optional[Dict]:
    """Read current simulated state for a resource."""
    from backend.database.db import SimulatedStateRepository
    repo = SimulatedStateRepository(db_session)
    obj = repo.get(resource_id)
    if obj:
        return dict(obj.state)
    return None


def _update_simulated_state(resource_id: str, new_state: Dict, db_session) -> bool:
    """Update simulated state for a resource."""
    from backend.database.db import SimulatedStateRepository
    repo = SimulatedStateRepository(db_session)
    result = repo.update_state(resource_id, new_state)
    return result is not None


# ============================================================
# IAM Tools
# ============================================================

def disable_access_key(
    key_id: str,
    user: str,
    db_session,
    agent: AgentName = AgentName.REMEDIATION,
    incident_id: Optional[str] = None,
) -> Tuple[ToolCall, ToolResult]:
    """
    Disable an IAM access key in the simulated environment.
    Reversible — key can be re-enabled.
    """
    call = ToolCall(
        tool_name="disable_access_key",
        agent=agent,
        incident_id=incident_id,
        arguments={"key_id": key_id, "user": user},
    )

    # Try resource_id patterns
    resource_candidates = [key_id, f"key_{user}_001"]

    before_state = None
    resource_id_used = None
    for candidate in resource_candidates:
        state = _get_simulated_state(candidate, db_session)
        if state is not None:
            before_state = state
            resource_id_used = candidate
            break

    if before_state is None:
        # Create it on the fly (key was just created by attacker)
        resource_id_used = key_id
        before_state = {"enabled": True, "user": user}

    if not before_state.get("enabled", True):
        return call, ToolResult(
            tool_id=call.tool_id,
            tool_name=call.tool_name,
            success=True,
            data={
                "status": RemediationStatus.SUCCESS,
                "message": "Key was already disabled",
                "before_state": before_state,
                "after_state": before_state,
            },
        )

    new_state = {**before_state, "enabled": False, "disabled_at": datetime.utcnow().isoformat()}
    _update_simulated_state(resource_id_used, new_state, db_session)

    logger.info("[REMEDIATION] disable_access_key: %s (user=%s) SUCCESS", key_id, user)
    return call, ToolResult(
        tool_id=call.tool_id,
        tool_name=call.tool_name,
        success=True,
        data={
            "status": RemediationStatus.SUCCESS,
            "resource_id": resource_id_used,
            "before_state": before_state,
            "after_state": new_state,
        },
    )


def enable_access_key(
    key_id: str,
    user: str,
    db_session,
    agent: AgentName = AgentName.REMEDIATION,
    incident_id: Optional[str] = None,
) -> Tuple[ToolCall, ToolResult]:
    """Re-enable a previously disabled access key (rollback)."""
    call = ToolCall(
        tool_name="enable_access_key",
        agent=agent,
        incident_id=incident_id,
        arguments={"key_id": key_id, "user": user},
    )

    resource_candidates = [key_id, f"key_{user}_001"]
    for candidate in resource_candidates:
        before_state = _get_simulated_state(candidate, db_session)
        if before_state is not None:
            new_state = {**before_state, "enabled": True, "re_enabled_at": datetime.utcnow().isoformat()}
            _update_simulated_state(candidate, new_state, db_session)
            return call, ToolResult(
                tool_id=call.tool_id,
                tool_name=call.tool_name,
                success=True,
                data={"status": RemediationStatus.SUCCESS, "before_state": before_state, "after_state": new_state},
            )

    return call, ToolResult(
        tool_id=call.tool_id, tool_name=call.tool_name,
        success=False, error=f"Resource not found for key_id={key_id}"
    )


def detach_policy(
    user: str,
    policy_arn: str,
    db_session,
    agent: AgentName = AgentName.REMEDIATION,
    incident_id: Optional[str] = None,
) -> Tuple[ToolCall, ToolResult]:
    """Detach an IAM policy from a user in the simulated environment."""
    call = ToolCall(
        tool_name="detach_policy",
        agent=agent,
        incident_id=incident_id,
        arguments={"user": user, "policy_arn": policy_arn},
    )

    resource_id = f"user_{user}"
    before_state = _get_simulated_state(resource_id, db_session)
    if not before_state:
        before_state = {"policies": [], "admin_attached": False}

    policy_name = policy_arn.split("/")[-1]
    policies = [p for p in before_state.get("policies", []) if p != policy_name]
    new_state = {
        **before_state,
        "policies": policies,
        "admin_attached": "AdministratorAccess" in policies,
        "policy_detached_at": datetime.utcnow().isoformat(),
    }
    _update_simulated_state(resource_id, new_state, db_session)

    logger.info("[REMEDIATION] detach_policy: %s from user=%s SUCCESS", policy_name, user)
    return call, ToolResult(
        tool_id=call.tool_id,
        tool_name=call.tool_name,
        success=True,
        data={"status": RemediationStatus.SUCCESS, "before_state": before_state, "after_state": new_state},
    )


def revoke_policy(
    user: str,
    policy_arn: str,
    db_session,
    agent: AgentName = AgentName.REMEDIATION,
    incident_id: Optional[str] = None,
) -> Tuple[ToolCall, ToolResult]:
    """Alias for detach_policy."""
    return detach_policy(user, policy_arn, db_session, agent, incident_id)


# ============================================================
# S3 Tools
# ============================================================

def make_bucket_private(
    bucket_name: str,
    db_session,
    agent: AgentName = AgentName.REMEDIATION,
    incident_id: Optional[str] = None,
) -> Tuple[ToolCall, ToolResult]:
    """Remove public access from an S3 bucket in the simulated environment."""
    call = ToolCall(
        tool_name="make_bucket_private",
        agent=agent,
        incident_id=incident_id,
        arguments={"bucket_name": bucket_name},
    )

    before_state = _get_simulated_state(bucket_name, db_session)
    if not before_state:
        before_state = {"public": True, "public_access_block": False}

    new_state = {
        **before_state,
        "public": False,
        "public_access_block": True,
        "made_private_at": datetime.utcnow().isoformat(),
    }
    _update_simulated_state(bucket_name, new_state, db_session)

    logger.info("[REMEDIATION] make_bucket_private: %s SUCCESS", bucket_name)
    return call, ToolResult(
        tool_id=call.tool_id,
        tool_name=call.tool_name,
        success=True,
        data={"status": RemediationStatus.SUCCESS, "before_state": before_state, "after_state": new_state},
    )


# ============================================================
# EC2 Tools
# ============================================================

def isolate_instance(
    instance_id: str,
    db_session,
    agent: AgentName = AgentName.REMEDIATION,
    incident_id: Optional[str] = None,
) -> Tuple[ToolCall, ToolResult]:
    """Apply quarantine security group to an EC2 instance in the simulated environment."""
    call = ToolCall(
        tool_name="isolate_instance",
        agent=agent,
        incident_id=incident_id,
        arguments={"instance_id": instance_id},
    )

    before_state = _get_simulated_state(instance_id, db_session)
    if not before_state:
        before_state = {"running": True, "security_groups": ["sg-normal-001"], "quarantined": False}

    new_state = {
        **before_state,
        "security_groups": ["sg-quarantine-000"],
        "quarantined": True,
        "quarantined_at": datetime.utcnow().isoformat(),
        "original_sgs": before_state.get("security_groups", []),
    }
    _update_simulated_state(instance_id, new_state, db_session)

    logger.info("[REMEDIATION] isolate_instance: %s SUCCESS", instance_id)
    return call, ToolResult(
        tool_id=call.tool_id,
        tool_name=call.tool_name,
        success=True,
        data={"status": RemediationStatus.SUCCESS, "before_state": before_state, "after_state": new_state},
    )


def restore_instance_sg(
    instance_id: str,
    db_session,
    agent: AgentName = AgentName.REMEDIATION,
    incident_id: Optional[str] = None,
) -> Tuple[ToolCall, ToolResult]:
    """Restore original security groups (rollback for isolate_instance)."""
    call = ToolCall(
        tool_name="restore_instance_sg",
        agent=agent,
        incident_id=incident_id,
        arguments={"instance_id": instance_id},
    )

    before_state = _get_simulated_state(instance_id, db_session)
    if not before_state:
        return call, ToolResult(
            tool_id=call.tool_id, tool_name=call.tool_name,
            success=False, error=f"Instance {instance_id} not found in simulated state"
        )

    original_sgs = before_state.get("original_sgs", ["sg-normal-001"])
    new_state = {
        **before_state,
        "security_groups": original_sgs,
        "quarantined": False,
        "restored_at": datetime.utcnow().isoformat(),
    }
    _update_simulated_state(instance_id, new_state, db_session)

    return call, ToolResult(
        tool_id=call.tool_id,
        tool_name=call.tool_name,
        success=True,
        data={"status": RemediationStatus.SUCCESS, "before_state": before_state, "after_state": new_state},
    )


# ============================================================
# Verification
# ============================================================

def verify_remediation(
    action_type: str,
    target: str,
    expected_state: Dict[str, Any],
    db_session,
    agent: AgentName = AgentName.REMEDIATION,
    incident_id: Optional[str] = None,
) -> Tuple[ToolCall, ToolResult]:
    """
    Verify that a remediation action was applied correctly by
    reading the current simulated state and comparing to expected_state.
    """
    call = ToolCall(
        tool_name="verify_remediation",
        agent=agent,
        incident_id=incident_id,
        arguments={"action_type": action_type, "target": target, "expected": expected_state},
    )

    current_state = _get_simulated_state(target, db_session)
    if current_state is None:
        # Try user_ prefix
        current_state = _get_simulated_state(f"user_{target}", db_session)

    if current_state is None:
        return call, ToolResult(
            tool_id=call.tool_id, tool_name=call.tool_name,
            success=False,
            error=f"Cannot read state for target '{target}' — verification failed",
            data={"verification_status": VerificationStatus.FAILED},
        )

    # Check each expected key
    mismatches = []
    for k, v in expected_state.items():
        actual = current_state.get(k)
        if actual != v:
            mismatches.append({"key": k, "expected": v, "actual": actual})

    verified = len(mismatches) == 0

    logger.info(
        "[VERIFICATION] %s on %s: %s",
        action_type, target,
        "VERIFIED" if verified else f"FAILED ({mismatches})"
    )

    return call, ToolResult(
        tool_id=call.tool_id,
        tool_name=call.tool_name,
        success=True,
        data={
            "verification_status": VerificationStatus.VERIFIED if verified else VerificationStatus.FAILED,
            "verified": verified,
            "current_state": current_state,
            "expected_state": expected_state,
            "mismatches": mismatches,
        },
    )


# ============================================================
# Dispatcher
# ============================================================

TOOL_DISPATCH: Dict[str, Any] = {
    "disable_access_key": disable_access_key,
    "enable_access_key": enable_access_key,
    "detach_policy": detach_policy,
    "revoke_policy": revoke_policy,
    "make_bucket_private": make_bucket_private,
    "isolate_instance": isolate_instance,
    "restore_instance_sg": restore_instance_sg,
}


def get_tool(action_type: str):
    """Get a remediation tool function by action type."""
    return TOOL_DISPATCH.get(action_type)
