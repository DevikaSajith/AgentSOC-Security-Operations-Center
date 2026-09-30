"""Reading and comparing the current state of a remediation target. Reads go through the ToolExecutor as the
Remediation Agent (read tool `get_resource`); nothing here can change anything."""

import hashlib
import json
from typing import Any

from app.agents.redaction import sanitize, summarize_iam_user
from app.agents.remediation.config import ActionPolicy
from app.domain.enums import AgentName
from app.tools.base import ToolRequest
from app.tools.executor import ToolExecutor

LOOKUP_TYPES = ("IAMUser", "EC2Instance", "S3Bucket")


def target_label(resource_type: str, resource_id: str) -> str:
    return f"{resource_type}/{resource_id}"


def parse_target(target: str | None) -> tuple[str, str] | None:
    """'IAMUser/alice' -> ('IAMUser', 'alice'); None if malformed or not a known resource type."""
    if not target or target.count("/") != 1:
        return None
    resource_type, resource_id = target.split("/", 1)
    if resource_type not in LOOKUP_TYPES or not resource_id:
        return None
    return resource_type, resource_id


def read_state(tools: ToolExecutor | None, incident_id: str, resource_type: str,
               resource_id: str, actor: AgentName = AgentName.REMEDIATION) -> dict[str, Any] | None:
    """The target's current raw state (via get_resource as the Remediation Agent), or None if it
    does not exist / cannot be read. The raw state stays inside the backend; the model only ever
    sees `safe_summary`."""
    if tools is None or resource_type not in LOOKUP_TYPES:
        return None
    result = tools.execute(ToolRequest(
        tool_name="get_resource", requested_by=actor, incident_id=incident_id,
        arguments={"resource_type": resource_type, "resource_id": resource_id},
        reason="remediation: current state of the target"))
    if not result.ok:
        return None
    return dict(result.output.get("state", {}))


def safe_summary(resource_type: str, state: dict[str, Any], max_len: int = 240) -> dict[str, Any]:
    """State without key ids, ids or credentials (safe for the model, the audit trail and the UI)."""
    if resource_type == "IAMUser":
        summary = summarize_iam_user(state)
        summary["access_key_active"] = bool(state.get("access_key_active"))
        return summary
    return sanitize({k: v for k, v in state.items() if k != "id"}, max_len)


def fingerprint(state: dict[str, Any], fields: tuple[str, ...]) -> str:
    relevant = {f: state.get(f) for f in fields}
    return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()


def satisfies(state: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(state.get(k) == v for k, v in expected.items())


def is_applicable(state: dict[str, Any], policy: ActionPolicy) -> bool:
    return satisfies(state, policy.requires_state)


def is_remediated(state: dict[str, Any], policy: ActionPolicy) -> bool:
    return satisfies(state, policy.postcondition)
