import pytest
from pydantic import ValidationError

from app.config import Settings
from app.database.connection import Database
from app.domain.enums import AgentName, ApprovalStatus, HumanActor
from app.simulator.attacks import AttackSimulator
from app.simulator.cloud import CloudSimulator
from app.services.event_service import EventService
from app.tools.base import ApprovalGrant, ToolContext, ToolKind, ToolRequest
from app.tools.executor import ToolExecutor
from app.tools.registry import (
    ACTION_TOOL_NAMES,
    DEFAULT_PERMISSIONS,
    build_default_registry,
)

READ_TOOL_NAMES = {"get_incident", "get_resource", "get_iam_entity", "get_cloudtrail_events",
                   "get_security_findings", "get_network_events", "get_asset_context",
                   "get_mitre_technique", "check_policy"}


def request(tool: str, actor, **kwargs) -> ToolRequest:
    arguments = kwargs.pop("arguments", {})
    return ToolRequest(tool_name=tool, arguments=arguments, requested_by=actor, **kwargs)


def approval(tool: str, incident_id: str = "INC-1",
             status: ApprovalStatus = ApprovalStatus.APPROVED) -> ApprovalGrant:
    return ApprovalGrant(approval_id="APR-1", incident_id=incident_id, tool_name=tool,
                         status=status, decided_by="analyst@example.test")


# -------------------------------------------------------------------- registry
def test_registry_contains_exactly_the_allow_listed_tools() -> None:
    registry = build_default_registry()
    assert {s.name for s in registry.list_specs(ToolKind.READ)} == READ_TOOL_NAMES
    assert {s.name for s in registry.list_specs(ToolKind.ACTION)} == ACTION_TOOL_NAMES
    assert all(s.requires_approval for s in registry.list_specs(ToolKind.ACTION))
    assert not any(s.requires_approval for s in registry.list_specs(ToolKind.READ))


def test_only_remediation_agent_and_analyst_hold_action_tools() -> None:
    holders = {actor for actor, names in DEFAULT_PERMISSIONS.items() if names & ACTION_TOOL_NAMES}
    assert holders == {AgentName.REMEDIATION, HumanActor.ANALYST}


def test_agent_actions_are_disabled_by_default() -> None:
    assert build_default_registry().agent_actions_enabled is False


# ----------------------------------------------------------- request validation
def test_tool_request_rejects_arbitrary_shapes() -> None:
    with pytest.raises(ValidationError):  # not a tool name, looks like a command
        request("rm -rf /", AgentName.REMEDIATION)
    with pytest.raises(ValidationError):  # unknown top-level field
        ToolRequest(tool_name="get_resource", requested_by=AgentName.TRIAGE, command="ls")
    with pytest.raises(ValidationError):  # unknown actor
        request("get_resource", "Rogue Agent")


def test_unknown_tool_is_rejected(executor: ToolExecutor, audit_log: list) -> None:
    result = executor.execute(request("delete_bucket", HumanActor.ANALYST))
    assert result.outcome == "invalid" and result.error_code == "unknown_tool"
    assert audit_log[-1].decision == "invalid"


@pytest.mark.parametrize("arguments", [
    {},                                       # missing
    {"instance_id": "ec2-001; shutdown -h"},  # injection characters
    {"instance_id": "../../etc/passwd"},      # path traversal-ish start
    {"instance_id": "ec2-001", "force": True},  # unexpected extra argument
])
def test_invalid_arguments_are_rejected(executor: ToolExecutor, cloud: CloudSimulator,
                                        arguments: dict) -> None:
    result = executor.execute(request("isolate_instance", HumanActor.ANALYST,
                                      arguments=arguments))
    assert result.outcome == "invalid" and result.error_code == "invalid_arguments"
    assert cloud.get_instance("ec2-001").status == "running"


# ----------------------------------------------------------------- permissions
@pytest.mark.parametrize("agent", [AgentName.MONITOR, AgentName.TRIAGE,
                                   AgentName.INVESTIGATOR, AgentName.COMPLIANCE])
def test_non_remediation_agents_cannot_act_even_with_approval(
        executor: ToolExecutor, cloud: CloudSimulator, agent: AgentName) -> None:
    result = executor.execute(request(
        "disable_access_key", agent, arguments={"username": "alice"}, incident_id="INC-1",
        approval=approval("disable_access_key")))
    assert result.outcome == "denied" and result.error_code == "permission_denied"
    assert cloud.get_user("alice").access_key_active is True


def test_read_permission_is_enforced(executor: ToolExecutor) -> None:
    denied = executor.execute(request("get_mitre_technique", AgentName.MONITOR,
                                      arguments={"technique_id": "T1098"}))
    assert denied.error_code == "permission_denied"
    allowed = executor.execute(request("get_mitre_technique", AgentName.INVESTIGATOR,
                                       arguments={"technique_id": "T1098.001"}))
    assert allowed.ok and allowed.output["parent_technique_id"] == "T1098"


def test_system_actor_has_no_tools(executor: ToolExecutor) -> None:
    result = executor.execute(request("get_resource", HumanActor.SYSTEM, arguments={
        "resource_type": "S3Bucket", "resource_id": "company-data"}))
    assert result.error_code == "permission_denied"


# -------------------------------------------------------------------- approval
def test_remediation_agent_blocked_while_agent_actions_disabled(
        executor: ToolExecutor, cloud: CloudSimulator, audit_log: list) -> None:
    result = executor.execute(request(
        "make_bucket_private", AgentName.REMEDIATION, arguments={"bucket_name": "public-assets"},
        incident_id="INC-1", approval=approval("make_bucket_private")))
    assert result.outcome == "denied" and result.error_code == "agent_actions_disabled"
    assert cloud.get_bucket("public-assets").public_access is True
    assert audit_log[-1].actor == AgentName.REMEDIATION and audit_log[-1].decision == "denied"


@pytest.fixture()
def enabled_executor(cloud: CloudSimulator, database: Database) -> ToolExecutor:
    """Future-phase configuration: agents may act, but only with a matching approval."""
    context = ToolContext(cloud=cloud, database=database,
                          registry=build_default_registry(agent_actions_enabled=True),
                          config_dir=Settings().config_dir)
    return ToolExecutor(context)


@pytest.mark.parametrize("grant, code", [
    (None, "approval_required"),
    (approval("isolate_instance", status=ApprovalStatus.PENDING), "approval_required"),
    (approval("isolate_instance", status=ApprovalStatus.REJECTED), "approval_required"),
    (approval("make_bucket_private"), "approval_mismatch"),            # other action
    (approval("isolate_instance", incident_id="INC-2"), "approval_mismatch"),  # other incident
])
def test_agent_action_needs_matching_approval(enabled_executor: ToolExecutor,
                                              cloud: CloudSimulator, grant, code: str) -> None:
    result = enabled_executor.execute(request(
        "isolate_instance", AgentName.REMEDIATION, arguments={"instance_id": "ec2-001"},
        incident_id="INC-1", approval=grant))
    assert result.outcome == "denied" and result.error_code == code
    assert cloud.get_instance("ec2-001").status == "running"


def test_agent_action_runs_with_matching_approval(enabled_executor: ToolExecutor,
                                                  cloud: CloudSimulator) -> None:
    result = enabled_executor.execute(request(
        "isolate_instance", AgentName.REMEDIATION, arguments={"instance_id": "ec2-001"},
        incident_id="INC-1", approval=approval("isolate_instance")))
    assert result.ok and result.output["new_state"] == {"status": "isolated"}
    assert cloud.get_instance("ec2-001").status == "isolated"


def test_analyst_action_executes_and_is_audited(executor: ToolExecutor, cloud: CloudSimulator,
                                                audit_log: list) -> None:
    cloud.make_user_admin("alice")
    result = executor.execute(request("remove_admin_privileges", HumanActor.ANALYST,
                                      arguments={"username": "alice"}))
    assert result.ok and cloud.get_user("alice").admin is False
    entry = audit_log[-1]
    assert entry.action == "tool:remove_admin_privileges" and entry.decision == "succeeded"
    assert entry.details["approved_by"] == "Human Analyst"


def test_action_on_missing_resource_fails_cleanly(executor: ToolExecutor) -> None:
    result = executor.execute(request("disable_access_key", HumanActor.ANALYST,
                                      arguments={"username": "mallory"}))
    assert result.outcome == "failed" and result.error_code == "resource_not_found"


# ------------------------------------------------------------------ read tools
def test_read_tools_return_simulated_data(executor: ToolExecutor, attacks: AttackSimulator,
                                          database: Database, audit_log: list) -> None:
    result = attacks.run("ec2_compromise")
    with database.session() as session:
        EventService(session).save_events(result.events)

    def call(tool: str, actor=AgentName.INVESTIGATOR, **arguments):
        outcome = executor.execute(request(tool, actor, arguments=arguments))
        assert outcome.ok, outcome.error
        return outcome.output

    assert len(call("get_cloudtrail_events", principal_id="bob")) == 3
    assert [e["event_type"] for e in call("get_network_events", resource_id="ec2-001")] == [
        "NetworkFlowAnomaly"]
    assert call("get_security_findings") == []  # GuardDuty/Security Hub not simulated yet
    context = call("get_asset_context", resource_id="ec2-001")
    assert context["resource_type"] == "EC2Instance"
    assert context["state"]["iam_role"] == "ec2-admin-role"
    assert len(context["recent_events"]) == 3
    policy = call("check_policy", actor=AgentName.COMPLIANCE, tool_name="isolate_instance")
    assert policy["requires_approval"] is True and policy["agent_execution_enabled"] is False
    assert "Remediation Agent" in policy["permitted_actors"]
    assert audit_log == []  # successful reads are not audited


def test_read_tool_not_found(executor: ToolExecutor) -> None:
    result = executor.execute(request("get_incident", AgentName.TRIAGE,
                                      arguments={"incident_id": "INC-404"}))
    assert result.outcome == "failed" and result.error_code == "resource_not_found"
