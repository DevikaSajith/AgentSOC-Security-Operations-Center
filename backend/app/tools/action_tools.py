"""ACTION tools: the only operations allowed to change (simulated) cloud state.

Each wraps exactly one allow-listed CloudSimulator method. Nothing here reaches real AWS.
The executor only runs them after the permission and human-approval checks.
"""

from typing import Any

from app.domain.enums import Severity
from app.simulator.cloud import ResourceNotFoundError
from app.simulator.resources import ActionResult
from app.tools.base import SafeIdentifier, ToolContext, ToolError, ToolInput, ToolKind, ToolSpec


class UserTarget(ToolInput):
    username: SafeIdentifier


class InstanceTarget(ToolInput):
    instance_id: SafeIdentifier


class BucketTarget(ToolInput):
    bucket_name: SafeIdentifier


def _run(action: Any, target: str) -> dict[str, Any]:
    try:
        result: ActionResult = action(target)
    except ResourceNotFoundError as exc:
        raise ToolError("resource_not_found", str(exc)) from None
    return result.model_dump(mode="json")


def disable_access_key(ctx: ToolContext, args: UserTarget) -> dict[str, Any]:
    return _run(ctx.cloud.disable_access_key, args.username)


def remove_admin_privileges(ctx: ToolContext, args: UserTarget) -> dict[str, Any]:
    return _run(ctx.cloud.remove_admin_privileges, args.username)


def isolate_instance(ctx: ToolContext, args: InstanceTarget) -> dict[str, Any]:
    return _run(ctx.cloud.isolate_instance, args.instance_id)


def make_bucket_private(ctx: ToolContext, args: BucketTarget) -> dict[str, Any]:
    return _run(ctx.cloud.make_bucket_private, args.bucket_name)


ACTION_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("disable_access_key", ToolKind.ACTION,
             "Deactivate all access keys of a simulated IAM user.",
             UserTarget, disable_access_key, risk=Severity.HIGH),
    ToolSpec("remove_admin_privileges", ToolKind.ACTION,
             "Revoke admin privileges from a simulated IAM user.",
             UserTarget, remove_admin_privileges, risk=Severity.HIGH),
    ToolSpec("isolate_instance", ToolKind.ACTION,
             "Quarantine a simulated EC2 instance.",
             InstanceTarget, isolate_instance, risk=Severity.HIGH),
    ToolSpec("make_bucket_private", ToolKind.ACTION,
             "Block public access to a simulated S3 bucket.",
             BucketTarget, make_bucket_private, risk=Severity.MEDIUM),
)
