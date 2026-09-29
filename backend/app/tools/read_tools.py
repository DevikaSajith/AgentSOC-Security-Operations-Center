"""READ tools: observe incidents, events, the simulated cloud and reference data.

They never change state, so they never need approval (permissions still apply).
"""

from typing import Any, Literal

from pydantic import Field

from app.domain.enums import EventSource
from app.knowledge.mitre import get_technique
from app.services.event_service import EventService
from app.services.incident_service import IncidentService
from app.simulator.cloud import ResourceNotFoundError
from app.tools.base import SafeIdentifier, ToolContext, ToolError, ToolInput, ToolKind, ToolSpec

ResourceType = Literal["IAMUser", "EC2Instance", "S3Bucket"]


def _events(ctx: ToolContext, *, sources: tuple[EventSource, ...] | None = None,
            limit: int, **filters: Any) -> list[dict[str, Any]]:
    if ctx.database is None:
        raise ToolError("database_unavailable", "event store is not configured")
    ctx.database.ensure_schema()
    with ctx.database.session() as session:
        service = EventService(session)
        if sources is None:
            events = service.list_events(limit=limit, **filters)
        else:
            events = [e for s in sources
                      for e in service.list_events(limit=limit, source=s.value, **filters)]
            events = sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]
    return [e.model_dump(mode="json") for e in events]


def _lookup_resource(ctx: ToolContext, resource_type: ResourceType,
                     resource_id: str) -> dict[str, Any]:
    getter = {"IAMUser": ctx.cloud.get_user, "EC2Instance": ctx.cloud.get_instance,
              "S3Bucket": ctx.cloud.get_bucket}[resource_type]
    try:
        return {"resource_type": resource_type,
                "resource_id": resource_id,
                "state": getter(resource_id).model_dump(mode="json")}
    except ResourceNotFoundError as exc:
        raise ToolError("resource_not_found", str(exc)) from None


# ----------------------------------------------------------------------------- inputs
class GetIncidentInput(ToolInput):
    incident_id: SafeIdentifier


class GetResourceInput(ToolInput):
    resource_type: ResourceType
    resource_id: SafeIdentifier


class GetIamEntityInput(ToolInput):
    username: SafeIdentifier


class EventQueryInput(ToolInput):
    principal_id: SafeIdentifier | None = None
    resource_id: SafeIdentifier | None = None
    event_type: SafeIdentifier | None = None
    limit: int = Field(default=50, ge=1, le=500)


class ResourceEventsInput(ToolInput):
    resource_id: SafeIdentifier | None = None
    limit: int = Field(default=50, ge=1, le=500)


class GetAssetContextInput(ToolInput):
    resource_id: SafeIdentifier
    limit: int = Field(default=25, ge=1, le=200)


class GetMitreTechniqueInput(ToolInput):
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")


class CheckPolicyInput(ToolInput):
    tool_name: SafeIdentifier


# --------------------------------------------------------------------------- handlers
def get_incident(ctx: ToolContext, args: GetIncidentInput) -> dict[str, Any]:
    if ctx.database is None:
        raise ToolError("database_unavailable", "incident store is not configured")
    ctx.database.ensure_schema()
    with ctx.database.session() as session:
        incident = IncidentService(session).get(args.incident_id)
    if incident is None:
        raise ToolError("resource_not_found", f"incident '{args.incident_id}' not found")
    return incident.model_dump(mode="json")


def get_resource(ctx: ToolContext, args: GetResourceInput) -> dict[str, Any]:
    return _lookup_resource(ctx, args.resource_type, args.resource_id)


def get_iam_entity(ctx: ToolContext, args: GetIamEntityInput) -> dict[str, Any]:
    return _lookup_resource(ctx, "IAMUser", args.username)


def get_cloudtrail_events(ctx: ToolContext, args: EventQueryInput) -> list[dict[str, Any]]:
    return _events(ctx, sources=(EventSource.CLOUDTRAIL,), limit=args.limit,
                   user=args.principal_id, resource_id=args.resource_id,
                   event_type=args.event_type)


def get_security_findings(ctx: ToolContext, args: ResourceEventsInput) -> list[dict[str, Any]]:
    # GuardDuty / Security Hub findings are not simulated yet, so this is empty for now.
    return _events(ctx, sources=(EventSource.GUARDDUTY, EventSource.SECURITY_HUB),
                   limit=args.limit, resource_id=args.resource_id)


def get_network_events(ctx: ToolContext, args: ResourceEventsInput) -> list[dict[str, Any]]:
    return _events(ctx, sources=(EventSource.VPC_FLOW_LOGS,), limit=args.limit,
                   resource_id=args.resource_id)


def get_asset_context(ctx: ToolContext, args: GetAssetContextInput) -> dict[str, Any]:
    resource = None
    for resource_type in ("IAMUser", "EC2Instance", "S3Bucket"):
        try:
            resource = _lookup_resource(ctx, resource_type, args.resource_id)  # type: ignore[arg-type]
            break
        except ToolError:
            continue
    if resource is None:
        raise ToolError("resource_not_found", f"resource '{args.resource_id}' not found")
    field = "user" if resource["resource_type"] == "IAMUser" else "resource_id"
    return {**resource,
            "recent_events": _events(ctx, limit=args.limit, **{field: args.resource_id})}


def get_mitre_technique(ctx: ToolContext, args: GetMitreTechniqueInput) -> dict[str, Any]:
    technique = get_technique(ctx.config_dir, args.technique_id)
    if technique is None:
        raise ToolError("resource_not_found",
                        f"technique '{args.technique_id}' is not in the knowledge base")
    return technique


def check_policy(ctx: ToolContext, args: CheckPolicyInput) -> dict[str, Any]:
    """The guardrail policy for a tool: who may call it and whether approval is needed."""
    spec = ctx.registry.get(args.tool_name)
    if spec is None:
        raise ToolError("unknown_tool", f"tool '{args.tool_name}' is not registered")
    return {
        "tool_name": spec.name,
        "kind": spec.kind.value,
        "risk": spec.risk.value,
        "reversible": spec.reversible,
        "requires_approval": spec.requires_approval,
        "permitted_actors": sorted(a.value for a in ctx.registry.actors_permitted(spec.name)),
        "agent_execution_enabled": ctx.registry.agent_actions_enabled
        if spec.kind == ToolKind.ACTION else True,
    }


READ_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("get_incident", ToolKind.READ, "Fetch one incident's full IncidentState.",
             GetIncidentInput, get_incident),
    ToolSpec("get_resource", ToolKind.READ, "Current state of one simulated cloud resource.",
             GetResourceInput, get_resource),
    ToolSpec("get_iam_entity", ToolKind.READ, "Current state of one simulated IAM user.",
             GetIamEntityInput, get_iam_entity),
    ToolSpec("get_cloudtrail_events", ToolKind.READ,
             "Stored CloudTrail events, filtered by principal / resource / event type.",
             EventQueryInput, get_cloudtrail_events),
    ToolSpec("get_security_findings", ToolKind.READ,
             "GuardDuty / Security Hub findings (none are simulated yet).",
             ResourceEventsInput, get_security_findings),
    ToolSpec("get_network_events", ToolKind.READ, "Stored VPC Flow Log events.",
             ResourceEventsInput, get_network_events),
    ToolSpec("get_asset_context", ToolKind.READ,
             "A resource's current state plus its recent events.",
             GetAssetContextInput, get_asset_context),
    ToolSpec("get_mitre_technique", ToolKind.READ,
             "Reference data for one MITRE ATT&CK technique.",
             GetMitreTechniqueInput, get_mitre_technique),
    ToolSpec("check_policy", ToolKind.READ,
             "Guardrail policy for a tool: permitted actors, approval, risk.",
             CheckPolicyInput, check_policy),
)
