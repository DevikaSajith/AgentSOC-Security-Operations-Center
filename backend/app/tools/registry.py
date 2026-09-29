"""Tool registry and the actor -> tool permission matrix."""

from app.domain.enums import AgentName, HumanActor
from app.domain.incident import Actor
from app.tools.base import ToolKind, ToolSpec

ACTION_TOOL_NAMES = frozenset({"disable_access_key", "remove_admin_privileges",
                               "isolate_instance", "make_bucket_private"})

# Least privilege: each actor gets only the tools its role needs.
DEFAULT_PERMISSIONS: dict[Actor, frozenset[str]] = {
    AgentName.MONITOR: frozenset({
        "get_cloudtrail_events", "get_network_events", "get_security_findings",
        "get_resource"}),
    AgentName.TRIAGE: frozenset({
        "get_incident", "get_cloudtrail_events", "get_security_findings", "get_network_events",
        "get_asset_context", "get_iam_entity", "get_resource"}),
    AgentName.INVESTIGATOR: frozenset({
        "get_incident", "get_resource", "get_iam_entity", "get_cloudtrail_events",
        "get_security_findings", "get_network_events", "get_asset_context",
        "get_mitre_technique"}),
    AgentName.COMPLIANCE: frozenset({
        "get_incident", "get_resource", "get_iam_entity", "get_asset_context",
        "check_policy"}),
    AgentName.REMEDIATION: frozenset({
        "get_incident", "get_resource", "check_policy"}) | ACTION_TOOL_NAMES,
    HumanActor.ANALYST: frozenset({"get_incident", "get_resource", "check_policy"})
    | ACTION_TOOL_NAMES,
    HumanActor.SYSTEM: frozenset(),
}


class ToolRegistry:
    """Holds tool specs and who may call them.

    `agent_actions_enabled` is the global switch for agents executing ACTION tools (even
    with approval). It is off in this phase: no autonomous remediation.
    """

    def __init__(self, permissions: dict[Actor, frozenset[str]] | None = None,
                 agent_actions_enabled: bool = False) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._permissions = {actor: set(names)
                             for actor, names in (permissions or DEFAULT_PERMISSIONS).items()}
        self.agent_actions_enabled = agent_actions_enabled

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool '{spec.name}' is already registered")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def list_specs(self, kind: ToolKind | None = None) -> list[ToolSpec]:
        return [s for s in self._tools.values() if kind is None or s.kind == kind]

    def is_permitted(self, actor: Actor, tool_name: str) -> bool:
        return tool_name in self._tools and tool_name in self._permissions.get(actor, set())

    def permissions_for(self, actor: Actor) -> list[str]:
        return sorted(n for n in self._permissions.get(actor, set()) if n in self._tools)

    def actors_permitted(self, tool_name: str) -> list[Actor]:
        return [a for a, names in self._permissions.items() if tool_name in names]


def build_default_registry(agent_actions_enabled: bool = False) -> ToolRegistry:
    """Registry with every read and action tool and the default permission matrix."""
    from app.tools.action_tools import ACTION_TOOLS
    from app.tools.read_tools import READ_TOOLS

    registry = ToolRegistry(agent_actions_enabled=agent_actions_enabled)
    for spec in (*READ_TOOLS, *ACTION_TOOLS):
        registry.register(spec)
    unknown = {n for names in DEFAULT_PERMISSIONS.values() for n in names} - {
        s.name for s in registry.list_specs()}
    if unknown:
        raise RuntimeError(f"permission matrix references unregistered tools: {sorted(unknown)}")
    return registry
