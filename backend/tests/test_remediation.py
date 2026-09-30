"""Remediation Agent tests. The LLM is always the deterministic MockLLMProvider (no Ollama needed).

The authority chain under test:  model proposal -> backend validation -> policy -> human approval
-> kill switch -> ToolExecutor -> simulator -> read-back."""

import json
import re
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.agents.remediation.agent import RemediationAgent, RemediationRunRequest
from app.agents.remediation.config import (
    RemediationConfigError,
    RemediationPolicy,
    load_remediation_settings,
)
from app.agents.remediation.context import RemediationContextBuilder
from app.agents.remediation.execution import (
    ApprovalNotFoundError,
    ApprovalStateError,
    RemediationExecutor,
)
from app.agents.remediation.prompts import SYSTEM_PROMPT
from app.agents.remediation.validation import RemediationValidationError, validate_decision
from app.config import Settings, get_settings
from app.database.connection import Database
from app.domain.enums import AgentName, AgentRunStatus, ApprovalStatus, IncidentStatus
from app.domain.events import utcnow
from app.domain.incident import AuditEntry, IncidentState
from app.domain.remediation import (
    ApprovalState,
    ExecutionStatus,
    RemediationAction,
    RemediationDecision,
    RemediationMethod,
)
from app.llm.mock import MockLLMProvider
from app.main import create_app
from app.services.agent_runs import AgentRunService
from app.services.approvals import ApprovalService
from app.services.incident_service import IncidentService
from app.simulator.cloud import CloudSimulator
from app.simulator.resources import ActionResult
from app.tools.base import ApprovalGrant, ToolContext, ToolRequest
from app.tools.executor import ToolExecutor
from app.tools.registry import ACTION_TOOL_NAMES, build_default_registry
from tests.test_compliance import answer as compliance_answer
from tests.test_compliance import assess as run_compliance
from tests.test_compliance import make_agent as make_compliance
from tests.test_compliance import make_investigated
from tests.test_investigator import answer as investigation_answer
from tests.test_investigator import investigate, make_agent as make_investigator, make_incident
from tests.test_triage import answer as triage_answer

CONFIG_DIR = Settings().config_dir
POLICY = load_remediation_settings(CONFIG_DIR)
BACKEND = Path(__file__).resolve().parent.parent
REMEDIATION_SRC = BACKEND / "app" / "agents" / "remediation"


# ============================================================================ builders
def decision(**overrides) -> dict:
    """A valid model answer for the IAM scenario (AS1 IAMUser/alice, CS1 current state, EV3 AttachAdminPolicy)."""
    base = {
        "action": "remove_admin_privileges", "target": "IAMUser/alice",
        "reason": "alice attached AdministratorAccess to her own user from an untrusted IP; removing admin is the "
                  "least disruptive fix.",
        "evidence_ids": ["EV3", "AS1", "CS1"],
        "expected_effect": "alice no longer has administrator privileges.",
        "risk_level": "medium", "rollback_available": False, "requires_approval": True,
        "rollback_description": "No rollback tool is registered; an analyst must restore admin rights manually.",
        "confidence": 0.9, "unknowns": ["Whether alice legitimately needed admin rights is not known."],
    }
    return {**base, **overrides}


def answer(**overrides) -> str:
    return json.dumps(decision(**overrides))


def policy_with(**changes) -> RemediationPolicy:
    data = POLICY.model_dump(mode="json")
    for key, value in changes.items():
        data[key] = value
    return RemediationPolicy.model_validate(data)


def disabled(action: str) -> RemediationPolicy:
    data = POLICY.model_dump(mode="json")
    data["actions"][action]["enabled"] = False
    return RemediationPolicy.model_validate(data)


# ============================================================================ fixtures
@pytest.fixture()
def audit_entries() -> list[AuditEntry]:
    return []


@pytest.fixture()
def tools(cloud: CloudSimulator, database: Database, audit_entries) -> ToolExecutor:
    return ToolExecutor(ToolContext(cloud=cloud, database=database, registry=build_default_registry(),
                                    config_dir=CONFIG_DIR), audit_sink=audit_entries.append)


def make_compliant(database, cloud, tools, audit_entries, scenario="iam_privilege_escalation") -> str:
    if scenario == "iam_privilege_escalation":
        incident_id = make_investigated(database, cloud, tools, audit_entries, scenario)
        report = run_compliance(make_compliance(database, tools, audit_entries,
                                                MockLLMProvider([compliance_answer()])), incident_id)
        assert report.status == AgentRunStatus.SUCCESS, report.validation_errors
        return incident_id
    incident_id = make_incident(database, cloud, tools, scenario)           # other scenarios: rule-based stages
    down = MockLLMProvider(available=False)
    assert investigate(make_investigator(database, tools, audit_entries, down), incident_id,
                       allow_rule_based_fallback=True).status == AgentRunStatus.SUCCESS
    assert run_compliance(make_compliance(database, tools, audit_entries, down), incident_id,
                          allow_rule_based_fallback=True).status == AgentRunStatus.SUCCESS
    return incident_id


@pytest.fixture()
def incident_id(database, cloud, tools, audit_entries) -> str:
    return make_compliant(database, cloud, tools, audit_entries)


def load(database: Database, incident_id: str) -> IncidentState:
    with database.session() as session:
        return IncidentService(session).get(incident_id)


def make_agent(database, tools, audit_entries, provider, policy=POLICY) -> RemediationAgent:
    return RemediationAgent(database, policy, provider, tools, audit_sink=audit_entries.append)


def make_executor(database, tools, audit_entries, policy=POLICY, clock=utcnow) -> RemediationExecutor:
    return RemediationExecutor(database, policy, tools, audit_sink=audit_entries.append, clock=clock)


def plan(agent: RemediationAgent, incident_id: str, **kwargs):
    return agent.run(RemediationRunRequest(incident_id=incident_id, **kwargs))


def proposed(database, tools, audit_entries, incident_id, **overrides):
    report = plan(make_agent(database, tools, audit_entries, MockLLMProvider([answer(**overrides)])), incident_id)
    assert report.status == AgentRunStatus.SUCCESS, report.validation_errors
    return report


def enable_actions(tools: ToolExecutor, on: bool = True) -> None:
    tools.registry.agent_actions_enabled = on


def build_context(database, tools, incident_id, policy=POLICY):
    return RemediationContextBuilder(policy, tools).build(load(database, incident_id))


def rejected(database, tools, incident_id, text: str) -> RemediationValidationError:
    with pytest.raises(RemediationValidationError) as info:
        validate_decision(text, build_context(database, tools, incident_id), POLICY)
    return info.value


def tool_audits(audit_entries, tool: str) -> list[AuditEntry]:
    return [e for e in audit_entries if e.action == f"tool:{tool}" and e.decision == "succeeded"]


# ================================================================================ planning
def test_valid_remediation_plan(database, cloud, tools, audit_entries, incident_id) -> None:
    report = proposed(database, tools, audit_entries, incident_id)
    assert report.outcome == "remediation_proposed" and report.method == RemediationMethod.LLM
    r = report.remediation
    assert (r.plan.action, r.plan.target, r.plan.arguments) == (
        RemediationAction.REMOVE_ADMIN_PRIVILEGES, "IAMUser/alice", {"username": "alice"})
    assert r.status == ExecutionStatus.PENDING_APPROVAL and r.plan.risk.value == "medium"
    assert report.approval.status == ApprovalState.PENDING and report.agent_result.proposed_actions[0].tool_name == \
        "remove_admin_privileges"
    assert cloud.get_user("alice").admin is True                              # planning changes NOTHING
    assert tool_audits(audit_entries, "remove_admin_privileges") == []


def test_no_action_plan(database, cloud, tools, audit_entries, incident_id) -> None:
    report = proposed(database, tools, audit_entries, incident_id, action="no_action", target=None, evidence_ids=[],
                      reason="The evidence does not establish that removing admin is safe; a human should decide.",
                      expected_effect="No change to the simulated cloud.", risk_level="info", requires_approval=False)
    assert report.outcome == "no_action" and report.approval is None
    incident = load(database, incident_id)
    assert incident.remediation.plan.action == RemediationAction.NO_ACTION and incident.remediation.status == \
        ExecutionStatus.NOT_EXECUTED
    assert incident.final_status == IncidentStatus.COMPLIANCE_ASSESSED          # no approval, no lifecycle change
    with database.session() as session:
        assert ApprovalService(session).list() == []
    assert cloud.get_user("alice").admin is True


@pytest.mark.parametrize("override,code", [
    ({"action": "delete_database"}, "schema_invalid"),
    ({"action": "rotate_all_credentials"}, "schema_invalid"),
    ({"action": "isolate_instance", "target": "EC2Instance/ec2-001"}, "invalid_action"),   # real action, not a candidate
])
def test_invalid_action_is_rejected(database, tools, incident_id, override, code) -> None:
    assert rejected(database, tools, incident_id, answer(**override)).code == code


def test_invalid_target_is_rejected(database, tools, incident_id) -> None:
    for target in ("IAMUser/bob", "IAMUser/mallory", "alice", "EC2Instance/ec2-001", None):
        err = rejected(database, tools, incident_id, answer(target=target))
        assert err.code == "invalid_target"


def test_invalid_evidence_is_rejected(database, tools, incident_id) -> None:
    err = rejected(database, tools, incident_id, answer(evidence_ids=["EV3", "EV999"]))
    assert err.code == "invalid_evidence_ref" and "EV999" in err.problems[0]


def test_action_needs_observed_evidence(database, tools, incident_id) -> None:
    err = rejected(database, tools, incident_id, answer(evidence_ids=["IF1", "TR1"]))     # opinions only
    assert err.code == "policy_violation" and "OBSERVED" in err.problems[0]
    assert rejected(database, tools, incident_id, answer(evidence_ids=[])).code == "policy_violation"


def test_unknown_fields_are_rejected(database, tools, incident_id) -> None:
    for extra in ({"command": "aws iam detach-user-policy"}, {"arguments": {"username": "bob"}}, {"tool": "x"}):
        assert rejected(database, tools, incident_id, json.dumps({**decision(), **extra})).code == "schema_invalid"


@pytest.mark.parametrize("overrides", [{"confidence": 1.5}, {"confidence": -0.1}, {"confidence": "high"},
                                       {"risk_level": "catastrophic"}, {"reason": "x"}])
def test_invalid_field_values_are_rejected(database, tools, incident_id, overrides) -> None:
    assert rejected(database, tools, incident_id, answer(**overrides)).code == "schema_invalid"


def test_malformed_json_is_rejected(database, tools, incident_id) -> None:
    assert rejected(database, tools, incident_id, "not json at all").code == "invalid_json"


def test_llm_unavailable_creates_no_approval(database, cloud, tools, audit_entries, incident_id) -> None:
    before = load(database, incident_id)
    report = plan(make_agent(database, tools, audit_entries, MockLLMProvider(available=False)), incident_id)
    assert report.status == AgentRunStatus.FAILED and report.outcome == "llm_unavailable" and report.approval is None
    assert load(database, incident_id) == before and cloud.get_user("alice").admin is True
    with database.session() as session:
        assert ApprovalService(session).list() == []


def test_no_llm_configured(database, tools, audit_entries, incident_id) -> None:
    report = plan(make_agent(database, tools, audit_entries, None), incident_id)
    assert report.outcome == "llm_not_configured" and load(database, incident_id).remediation is None


def test_repair_succeeds(database, tools, audit_entries, incident_id) -> None:
    provider = MockLLMProvider([answer(target="IAMUser/bob"), answer()])
    report = plan(make_agent(database, tools, audit_entries, provider), incident_id)
    assert report.status == AgentRunStatus.SUCCESS and report.attempts == 2 and len(provider.calls) == 2
    assert "IAMUser/bob" in provider.calls[1]["user"] and "rejected" in provider.calls[1]["user"]
    assert report.remediation.plan.target == "IAMUser/alice"


def test_repair_prompt_names_the_observed_evidence(database, tools, audit_entries, incident_id) -> None:
    """Found with the real model: it cited only IF/MT/MF/TR opinions twice. The repair now lists observed ids."""
    provider = MockLLMProvider([answer(evidence_ids=["IF1", "TR1"]), answer()])
    report = plan(make_agent(database, tools, audit_entries, provider), incident_id)
    assert report.status == AgentRunStatus.SUCCESS and report.attempts == 2
    repair = provider.calls[1]["user"]
    assert "OBSERVED evidence ids you may cite" in repair and "CS1" in repair.split("Previous answer")[0]
    assert "Copy the OBSERVED ids" in provider.calls[0]["user"]


def test_repair_fails(database, cloud, tools, audit_entries, incident_id) -> None:
    provider = MockLLMProvider([answer(target="IAMUser/bob"), answer(evidence_ids=["EV999"])])
    report = plan(make_agent(database, tools, audit_entries, provider), incident_id)
    assert report.status == AgentRunStatus.FAILED and report.attempts == 2 and report.outcome == "invalid_llm_output"
    assert report.remediation is None and report.approval is None and load(database, incident_id).remediation is None
    assert cloud.get_user("alice").admin is True


# =================================================================================== policy
def test_disabled_action_is_blocked_at_planning(database, tools, audit_entries, incident_id) -> None:
    policy = disabled("remove_admin_privileges")
    ctx = build_context(database, tools, incident_id, policy)
    assert "remove_admin_privileges" not in {c.action.value for c in ctx.analysis.candidates}
    assert any("remove_admin_privileges" in x and "disabled by policy" in x for x in ctx.analysis.excluded)
    provider = MockLLMProvider([answer()])
    report = plan(make_agent(database, tools, audit_entries, provider, policy), incident_id)
    assert report.status == AgentRunStatus.FAILED and report.approval is None    # the model may not pick it


def test_protected_resource_is_blocked(database, tools, audit_entries, incident_id) -> None:
    policy = policy_with(protected_resources={"IAMUser/alice": "break-glass account"})
    ctx = build_context(database, tools, incident_id, policy)
    assert ctx.analysis.candidates == [] and any("protected resource" in x for x in ctx.analysis.excluded)
    report = plan(make_agent(database, tools, audit_entries, MockLLMProvider([answer()]), policy), incident_id)
    assert report.outcome == "no_action" and report.method == RemediationMethod.NO_CANDIDATES
    assert report.approval is None and not report.attempts                      # no candidates -> the model is not asked


def test_risk_policy_is_enforced(database, tools, audit_entries, incident_id) -> None:
    report = proposed(database, tools, audit_entries, incident_id, risk_level="low", rollback_available=True)
    plan_ = report.remediation.plan
    assert plan_.risk.value == "medium" and plan_.proposed_risk.value == "low" and report.approval.risk == "medium"
    notes = {n.field: n for n in plan_.policy_notes}
    assert notes["risk"].final == "medium" and "policy" in notes["risk"].note
    assert plan_.rollback_available is False and notes["rollback_available"].proposed == "true"


def test_approval_requirement_is_enforced(database, tools, audit_entries, incident_id) -> None:
    report = proposed(database, tools, audit_entries, incident_id, requires_approval=False)
    assert report.remediation.plan.requires_approval is True and report.approval.status == ApprovalState.PENDING
    assert {n.field for n in report.remediation.plan.policy_notes} == {"requires_approval"}


def test_policy_file_is_validated(tmp_path) -> None:
    good = (CONFIG_DIR / "remediation_policy.yaml").read_text(encoding="utf-8")
    (tmp_path / "remediation_policy.yaml").write_text(good.replace("  disable_access_key:\n", "  delete_database:\n", 1),
                                                      encoding="utf-8")
    with pytest.raises(RemediationConfigError, match="not registered action tools"):
        load_remediation_settings(tmp_path)
    (tmp_path / "remediation_policy.yaml").write_text(good.replace("requires_approval: true", "requires_approval: false", 1),
                                                      encoding="utf-8")
    with pytest.raises(RemediationConfigError, match="must require human approval"):
        load_remediation_settings(tmp_path)
    with pytest.raises(RemediationConfigError, match="not found"):
        load_remediation_settings(tmp_path / "missing")


def test_every_policy_action_needs_approval_and_has_a_tool() -> None:
    assert set(POLICY.actions) == set(ACTION_TOOL_NAMES)
    assert all(a.requires_approval for a in POLICY.actions.values())


# ================================================================================== approval
def test_approval_is_created(database, tools, audit_entries, incident_id) -> None:
    report = proposed(database, tools, audit_entries, incident_id)
    a = report.approval
    assert a.approval_id.startswith("APR-") and a.incident_id == incident_id and a.agent_run_id == report.run_id
    assert (a.action, a.target, a.arguments, a.risk) == ("remove_admin_privileges", "IAMUser/alice",
                                                        {"username": "alice"}, "medium")
    assert a.status == ApprovalState.PENDING and a.reviewed_at is None and a.reviewed_by is None
    assert a.expires_at - a.requested_at == timedelta(minutes=POLICY.approval.ttl_minutes)
    incident = load(database, incident_id)
    assert incident.final_status == IncidentStatus.REMEDIATION_PENDING and incident.current_agent == AgentName.REMEDIATION
    assert incident.remediation.approval.approval_id == a.approval_id
    actions = [e.action for e in audit_entries]
    assert {"remediation.run", "remediation.proposed", "remediation.approval_requested"} <= set(actions)


def test_new_proposal_supersedes_the_old_one(database, tools, audit_entries, incident_id) -> None:
    first = proposed(database, tools, audit_entries, incident_id).approval
    second = proposed(database, tools, audit_entries, incident_id).approval
    with database.session() as session:
        service = ApprovalService(session)
        assert service.get(first.approval_id).status == ApprovalState.EXPIRED
        assert service.get(second.approval_id).status == ApprovalState.PENDING
    assert load(database, incident_id).remediation.approval.approval_id == second.approval_id


def test_reject_leaves_the_cloud_unchanged(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    report = make_executor(database, tools, audit_entries).reject(approval.approval_id, "not now")
    assert report.outcome == "rejected" and report.approval.status == ApprovalState.REJECTED
    assert report.approval.reviewed_by == "Human Analyst" and report.approval.decision == "not now"
    incident = load(database, incident_id)
    assert incident.final_status == IncidentStatus.REMEDIATION_REJECTED
    assert incident.remediation.execution.status == ExecutionStatus.REJECTED
    assert cloud.get_user("alice").admin is True and tool_audits(audit_entries, "remove_admin_privileges") == []
    assert "remediation.rejected" in [e.action for e in audit_entries]
    with pytest.raises(ApprovalStateError):                                       # cannot be decided twice
        make_executor(database, tools, audit_entries).approve(approval.approval_id)


def test_approve_executes_the_exact_action(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    report = make_executor(database, tools, audit_entries).approve(approval.approval_id)
    assert report.outcome == "executed" and report.execution.status == ExecutionStatus.EXECUTED
    assert cloud.get_user("alice").admin is False and cloud.get_user("bob").admin is False
    assert report.approval.status == ApprovalState.APPROVED and report.approval.executed_at is not None
    incident = load(database, incident_id)
    assert incident.final_status == IncidentStatus.REMEDIATED and incident.remediation.status == ExecutionStatus.EXECUTED


def test_wrong_approval_cannot_execute_another_action(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval

    def grant(**kw):
        return ApprovalGrant(approval_id=approval.approval_id, incident_id=incident_id, tool_name="remove_admin_privileges",
                             status=ApprovalStatus.APPROVED, decided_by="Human Analyst",
                             arguments={"username": "alice"}, **kw)

    other_action = tools.execute(ToolRequest(tool_name="disable_access_key", arguments={"username": "alice"},
                                             requested_by=AgentName.REMEDIATION, incident_id=incident_id, approval=grant()))
    other_target = tools.execute(ToolRequest(tool_name="remove_admin_privileges", arguments={"username": "bob"},
                                             requested_by=AgentName.REMEDIATION, incident_id=incident_id, approval=grant()))
    other_incident = tools.execute(ToolRequest(tool_name="remove_admin_privileges", arguments={"username": "alice"},
                                               requested_by=AgentName.REMEDIATION, incident_id="INC-OTHER", approval=grant()))
    assert [r.error_code for r in (other_action, other_target, other_incident)] == ["approval_mismatch"] * 3
    assert cloud.get_user("alice").admin is True and cloud.get_user("alice").access_key_active is True
    # and an approval for alice never touches bob
    make_executor(database, tools, audit_entries).approve(approval.approval_id)
    assert cloud.get_user("bob").access_key_active is True


def test_tampered_proposal_is_blocked(database, cloud, tools, audit_entries, incident_id) -> None:
    from app.database.models import ApprovalRecord
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    with database.session() as session:                                        # someone edits the stored arguments
        record = session.query(ApprovalRecord).filter_by(approval_id=approval.approval_id).one()
        record.arguments = {"username": "bob"}
        session.commit()
    report = make_executor(database, tools, audit_entries).approve(approval.approval_id)
    assert report.outcome == "proposal_tampered" and report.execution.status == ExecutionStatus.BLOCKED
    assert cloud.get_user("bob").admin is False and cloud.get_user("alice").admin is True


def test_expired_approval_is_blocked(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    later = lambda: utcnow() + timedelta(minutes=POLICY.approval.ttl_minutes + 1)  # noqa: E731
    with pytest.raises(ApprovalStateError) as info:
        make_executor(database, tools, audit_entries, clock=later).approve(approval.approval_id)
    assert info.value.code == "approval_expired"
    assert cloud.get_user("alice").admin is True and tool_audits(audit_entries, "remove_admin_privileges") == []
    with database.session() as session:
        assert ApprovalService(session).get(approval.approval_id).status == ApprovalState.EXPIRED
    assert load(database, incident_id).remediation.execution.reason_code == "approval_expired"


def test_unknown_approval(database, tools, audit_entries) -> None:
    with pytest.raises(ApprovalNotFoundError):
        make_executor(database, tools, audit_entries).approve("APR-NOPE")


# ================================================================================ kill switch
def test_actions_disabled_blocks_execution(database, cloud, tools, audit_entries, incident_id) -> None:
    assert tools.registry.agent_actions_enabled is False                        # the default
    approval = proposed(database, tools, audit_entries, incident_id).approval
    report = make_executor(database, tools, audit_entries).approve(approval.approval_id)
    assert report.outcome == "actions_disabled" and report.execution.status == ExecutionStatus.BLOCKED
    assert report.execution.reason_code == "actions_disabled"
    assert cloud.get_user("alice").admin is True
    assert tool_audits(audit_entries, "remove_admin_privileges") == []
    assert not [e for e in audit_entries if e.action == "tool:remove_admin_privileges"]   # the tool was never even called
    assert "remediation.blocked" in [e.action for e in audit_entries]


def test_approved_action_stays_blocked_until_the_switch_is_on(database, cloud, tools, audit_entries, incident_id) -> None:
    approval = proposed(database, tools, audit_entries, incident_id).approval
    executor = make_executor(database, tools, audit_entries)
    assert executor.approve(approval.approval_id).outcome == "actions_disabled"
    incident = load(database, incident_id)
    assert incident.final_status == IncidentStatus.REMEDIATION_APPROVED
    with database.session() as session:
        assert ApprovalService(session).get(approval.approval_id).status == ApprovalState.APPROVED
    assert executor.execute(approval.approval_id).outcome == "actions_disabled"          # still off
    assert cloud.get_user("alice").admin is True
    enable_actions(tools)
    assert executor.execute(approval.approval_id).outcome == "executed"
    assert cloud.get_user("alice").admin is False


def test_the_tool_layer_enforces_the_kill_switch_too(database, cloud, tools, audit_entries, incident_id) -> None:
    approval = proposed(database, tools, audit_entries, incident_id).approval
    result = tools.execute(ToolRequest(
        tool_name="remove_admin_privileges", arguments={"username": "alice"}, requested_by=AgentName.REMEDIATION,
        incident_id=incident_id, approval=ApprovalGrant(approval_id=approval.approval_id, incident_id=incident_id,
                                                        tool_name="remove_admin_privileges", status=ApprovalStatus.APPROVED,
                                                        decided_by="Human Analyst")))
    assert result.error_code == "agent_actions_disabled" and cloud.get_user("alice").admin is True


def test_kill_switch_setting_comes_from_the_environment(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_ACTIONS_ENABLED", raising=False)
    assert get_settings().agent_actions_enabled is False and Settings().agent_actions_enabled is False
    monkeypatch.setenv("AGENT_ACTIONS_ENABLED", "true")
    assert get_settings().agent_actions_enabled is True
    monkeypatch.setenv("AGENT_ACTIONS_ENABLED", "maybe")
    assert get_settings().agent_actions_enabled is False                        # anything unclear stays off


# ============================================================================ tool execution
def test_tool_executor_is_used(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    make_executor(database, tools, audit_entries).approve(approval.approval_id)
    [entry] = tool_audits(audit_entries, "remove_admin_privileges")
    assert entry.actor == AgentName.REMEDIATION
    assert entry.details["arguments"] == {"username": "alice"} and entry.details["approval_id"] == approval.approval_id


def test_remediation_code_cannot_touch_the_simulator_or_the_outside_world() -> None:
    sources = {p.name: p.read_text(encoding="utf-8") for p in REMEDIATION_SRC.glob("*.py")}
    assert sources
    for name, text in sources.items():
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(("#", '"""')))
        assert not re.search(r"^\s*(from|import)\s+app\.simulator", code, re.M), name        # no simulator access
        assert not re.search(r"\bCloudSimulator\b|\.cloud\.|make_user_admin|remove_admin_privileges\(", code), name
        assert not re.search(r"\b(subprocess|os\.system|os\.popen|eval|exec|shlex|pexpect)\b", code), name
        assert not re.search(r"^\s*(from|import)\s+(httpx|requests|urllib|socket|http\.client|aiohttp)", code, re.M), name


def test_the_decision_schema_has_no_place_for_arguments_or_commands() -> None:
    schema = RemediationDecision.model_json_schema()
    assert set(schema["properties"]) == {"action", "target", "reason", "evidence_ids", "expected_effect", "risk_level",
                                         "rollback_available", "rollback_description", "requires_approval", "confidence", "unknowns"}
    assert set(schema["$defs"]["RemediationAction"]["enum"]) == ACTION_TOOL_NAMES | {"no_action"}
    assert schema["additionalProperties"] is False


def test_invalid_arguments_are_rejected_by_the_tool_layer(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    for arguments in ({"username": "alice; rm -rf /"}, {"username": "alice", "extra": 1}, {"user": "alice"}, {}):
        result = tools.execute(ToolRequest(
            tool_name="remove_admin_privileges", arguments=arguments, requested_by=AgentName.REMEDIATION,
            incident_id=incident_id, approval=ApprovalGrant(approval_id=approval.approval_id, incident_id=incident_id,
                                                            tool_name="remove_admin_privileges",
                                                            status=ApprovalStatus.APPROVED, decided_by="Human Analyst")))
        assert result.error_code == "invalid_arguments"
    assert cloud.get_user("alice").admin is True


def test_permission_checks_are_enforced(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    grant = ApprovalGrant(approval_id=approval.approval_id, incident_id=incident_id, tool_name="remove_admin_privileges",
                          status=ApprovalStatus.APPROVED, decided_by="Human Analyst")
    for agent in (AgentName.MONITOR, AgentName.TRIAGE, AgentName.INVESTIGATOR, AgentName.COMPLIANCE):
        result = tools.execute(ToolRequest(tool_name="remove_admin_privileges", arguments={"username": "alice"},
                                           requested_by=agent, incident_id=incident_id, approval=grant))
        assert result.error_code == "permission_denied"
    assert cloud.get_user("alice").admin is True
    read = tools.registry.permissions_for(AgentName.REMEDIATION)
    assert {"get_incident", "get_resource", "get_iam_entity", "get_cloudtrail_events", "get_security_findings",
            "get_network_events", "get_asset_context", "check_policy"} <= set(read)
    assert set(read) & ACTION_TOOL_NAMES == ACTION_TOOL_NAMES


# ================================================================================= execution
def test_successful_execution_records_before_and_after(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    report = make_executor(database, tools, audit_entries).approve(approval.approval_id)
    e = report.execution
    assert (e.action, e.target, e.tool_name, e.approval_id) == (RemediationAction.REMOVE_ADMIN_PRIVILEGES, "IAMUser/alice",
                                                                "remove_admin_privileges", approval.approval_id)
    assert e.before_state["admin"] is True and e.after_state["admin"] is False and e.executed_at and e.tool_request_id
    stored = load(database, incident_id).remediation
    assert stored.before_state["admin"] is True and stored.after_state["admin"] is False
    executed = next(x for x in audit_entries if x.action == "remediation.executed")
    assert executed.details["before_state"]["admin"] is True and executed.details["after_state"]["admin"] is False
    assert executed.details["approval_id"] == approval.approval_id and executed.details["target"] == "IAMUser/alice"


def test_state_is_read_back_not_trusted(database, cloud, tools, audit_entries, incident_id, monkeypatch) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    monkeypatch.setattr(cloud, "remove_admin_privileges", lambda name: ActionResult(     # claims success, changes nothing
        success=True, resource=name, resource_type="IAMUser", action="remove_admin_privileges",
        old_state={"admin": True}, new_state={"admin": False}))
    report = make_executor(database, tools, audit_entries).approve(approval.approval_id)
    assert report.outcome == "execution_failed" or report.execution.reason_code == "readback_mismatch"
    assert report.execution.status == ExecutionStatus.FAILED and report.execution.reason_code == "readback_mismatch"
    assert cloud.get_user("alice").admin is True
    assert load(database, incident_id).final_status == IncidentStatus.REMEDIATION_FAILED


def test_failed_action_is_recorded(database, cloud, tools, audit_entries, incident_id, monkeypatch) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval

    def boom(_name):
        raise RuntimeError("simulated outage")

    monkeypatch.setattr(cloud, "remove_admin_privileges", boom)
    report = make_executor(database, tools, audit_entries).approve(approval.approval_id)
    assert report.execution.status == ExecutionStatus.FAILED and report.agent_result.status == AgentRunStatus.FAILED
    assert load(database, incident_id).final_status == IncidentStatus.REMEDIATION_FAILED
    assert "remediation.failed" in [e.action for e in audit_entries]
    assert cloud.get_user("alice").admin is True


def test_before_after_never_contain_key_ids(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    make_executor(database, tools, audit_entries).approve(approval.approval_id)
    blob = json.dumps(load(database, incident_id).remediation.model_dump(mode="json"))
    blob += json.dumps([e.model_dump(mode="json") for e in audit_entries if e.action.startswith("remediation.")])
    for key in cloud.get_user("alice").access_keys:
        assert key.key_id not in blob


# ================================================================================ idempotency
def test_same_action_cannot_execute_twice(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    executor = make_executor(database, tools, audit_entries)
    assert executor.approve(approval.approval_id).outcome == "executed"
    with pytest.raises(ApprovalStateError):
        executor.approve(approval.approval_id)                                   # already decided
    again = executor.execute(approval.approval_id)
    assert again.outcome == "already_remediated"
    assert len(tool_audits(audit_entries, "remove_admin_privileges")) == 1        # ToolExecutor ran exactly once
    incident = load(database, incident_id)
    assert incident.remediation.execution.status == ExecutionStatus.EXECUTED     # the record was not overwritten
    assert incident.final_status == IncidentStatus.REMEDIATED


def test_planning_again_after_execution_is_already_remediated(database, cloud, tools, audit_entries, incident_id) -> None:
    only_admin = disabled("disable_access_key")                                   # remove_admin was the only candidate
    enable_actions(tools)
    approval = plan(make_agent(database, tools, audit_entries, MockLLMProvider([answer()]), only_admin),
                    incident_id).approval
    make_executor(database, tools, audit_entries, only_admin).approve(approval.approval_id)
    provider = MockLLMProvider([answer()])
    report = plan(make_agent(database, tools, audit_entries, provider, only_admin), incident_id)
    assert report.outcome == "already_remediated" and report.status == AgentRunStatus.SKIPPED
    assert report.approval is None and provider.calls == []
    assert load(database, incident_id).remediation.execution.status == ExecutionStatus.EXECUTED
    with database.session() as session:
        assert len(ApprovalService(session).list()) == 1                          # no second approval


def test_an_executed_action_is_never_proposed_again(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    make_executor(database, tools, audit_entries).approve(approval.approval_id)
    ctx = build_context(database, tools, incident_id)
    assert RemediationAction.REMOVE_ADMIN_PRIVILEGES not in {c.action for c in ctx.analysis.candidates}
    assert any("already in the desired state" in x for x in ctx.analysis.already_remediated)
    again = plan(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    assert again.status == AgentRunStatus.FAILED and again.approval is None       # the model cannot re-propose it
    assert len(tool_audits(audit_entries, "remove_admin_privileges")) == 1


def test_existing_remediated_state_is_detected(database, cloud, tools, audit_entries, incident_id) -> None:
    cloud.remove_admin_privileges("alice")                                        # fixed out-of-band before planning
    ctx = build_context(database, tools, incident_id)
    assert not [c for c in ctx.analysis.candidates if c.action == RemediationAction.REMOVE_ADMIN_PRIVILEGES]
    assert any("remove_admin_privileges" in x and "already in the desired state" in x
               for x in ctx.analysis.already_remediated)
    report = plan(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    assert report.approval is None                                                # nothing to approve for admin


# ================================================================================== stale state
def stale_ec2(database, cloud, tools, audit_entries):
    incident_id = make_compliant(database, cloud, tools, audit_entries, "ec2_compromise")
    provider = MockLLMProvider([answer(action="isolate_instance", target="EC2Instance/ec2-001",
                                       reason="ec2-001 ran attacker commands and generated abnormal outbound traffic.",
                                       evidence_ids=["CS1"], risk_level="high",
                                       expected_effect="ec2-001 is quarantined.")])
    report = plan(make_agent(database, tools, audit_entries, provider), incident_id)
    assert report.status == AgentRunStatus.SUCCESS, report.validation_errors
    return incident_id, report


def test_stale_plan_is_blocked(database, cloud, tools, audit_entries) -> None:
    enable_actions(tools)
    incident_id, report = stale_ec2(database, cloud, tools, audit_entries)
    assert report.approval.action == "isolate_instance" and report.approval.arguments == {"instance_id": "ec2-001"}
    cloud.set_instance_role("ec2-001", "some-other-role")                         # the world changes after the proposal
    result = make_executor(database, tools, audit_entries).approve(report.approval.approval_id)
    assert result.outcome == "stale_remediation_plan" and result.execution.status == ExecutionStatus.BLOCKED
    assert result.execution.reason_code == "stale_remediation_plan"
    assert cloud.get_instance("ec2-001").status == "running"                      # nothing executed
    assert tool_audits(audit_entries, "isolate_instance") == []
    assert result.approval.status == ApprovalState.EXPIRED


def test_a_new_plan_is_required_after_a_stale_block(database, cloud, tools, audit_entries) -> None:
    enable_actions(tools)
    incident_id, report = stale_ec2(database, cloud, tools, audit_entries)
    cloud.set_instance_role("ec2-001", "some-other-role")
    executor = make_executor(database, tools, audit_entries)
    executor.approve(report.approval.approval_id)
    assert load(database, incident_id).final_status == IncidentStatus.COMPLIANCE_ASSESSED
    with pytest.raises(ApprovalStateError):                                       # the old approval is dead
        executor.execute(report.approval.approval_id)
    fresh = plan(make_agent(database, tools, audit_entries, MockLLMProvider([answer(
        action="isolate_instance", target="EC2Instance/ec2-001", evidence_ids=["CS1"], risk_level="high",
        reason="ec2-001 ran attacker commands and generated abnormal outbound traffic.",
        expected_effect="ec2-001 is quarantined.")])), incident_id)
    assert fresh.status == AgentRunStatus.SUCCESS and fresh.approval.approval_id != report.approval.approval_id
    assert executor.approve(fresh.approval.approval_id).outcome == "executed"
    assert cloud.get_instance("ec2-001").status == "isolated"


def test_policy_is_revalidated_before_execution(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    tighter = disabled("remove_admin_privileges")
    with database.session() as session:                                           # approve first, then tighten policy
        ApprovalService(session).transition(approval.approval_id, ApprovalState.APPROVED,
                                            allowed_from=(ApprovalState.PENDING,), reviewed_by="Human Analyst", decision=None)
    report = make_executor(database, tools, audit_entries, tighter).execute(approval.approval_id)
    assert report.outcome == "policy_blocked" and cloud.get_user("alice").admin is True


# ================================================================================== fallback
def test_rule_based_fallback_still_needs_approval_and_the_kill_switch(database, cloud, tools, audit_entries, incident_id) -> None:
    down = MockLLMProvider(available=False)
    report = plan(make_agent(database, tools, audit_entries, down), incident_id, allow_rule_based_fallback=True)
    assert report.status == AgentRunStatus.SUCCESS and report.method == RemediationMethod.RULE_BASED_FALLBACK
    assert report.outcome == "remediation_proposed_rule_based_fallback"
    assert report.remediation.plan.action == RemediationAction.REMOVE_ADMIN_PRIVILEGES          # least disruptive first
    assert report.approval.status == ApprovalState.PENDING and cloud.get_user("alice").admin is True
    blocked = make_executor(database, tools, audit_entries).approve(report.approval.approval_id)
    assert blocked.outcome == "actions_disabled" and cloud.get_user("alice").admin is True
    enable_actions(tools)
    assert make_executor(database, tools, audit_entries).execute(report.approval.approval_id).outcome == "executed"


def test_without_the_flag_there_is_no_fallback(database, tools, audit_entries, incident_id) -> None:
    report = plan(make_agent(database, tools, audit_entries, MockLLMProvider(available=False)), incident_id)
    assert report.method is None and report.approval is None


# ==================================================================================== security
def test_no_secrets_reach_the_llm(database, cloud, tools, audit_entries, incident_id) -> None:
    provider = MockLLMProvider([answer(target="IAMUser/bob"), answer()])          # includes a repair prompt
    plan(make_agent(database, tools, audit_entries, provider), incident_id)
    prompts = "\n".join(c["system"] + c["user"] for c in provider.calls)
    for key in cloud.get_user("alice").access_keys:
        assert key.key_id not in prompts
    assert not re.search(r"AKIA[A-Z0-9]{6,}", prompts)
    assert "other incidents" not in prompts and "bob" not in json.loads(
        build_context(database, tools, incident_id).to_json())["evidence"].__str__().lower()


def test_no_raw_llm_output_or_prompts_in_audit_or_runs(database, tools, audit_entries, incident_id) -> None:
    marker = "RAW_MODEL_MARKER_7431"
    provider = MockLLMProvider([f"garbage {marker} not json", answer(reason=f"alice escalated; fix is safe. {marker[:0]}")])
    report = plan(make_agent(database, tools, audit_entries, provider), incident_id)
    assert report.status == AgentRunStatus.SUCCESS
    blob = json.dumps([e.model_dump(mode="json") for e in audit_entries], default=str)
    with database.session() as session:
        blob += json.dumps(AgentRunService(session).stats("Remediation Agent"), default=str)
    assert marker not in blob and SYSTEM_PROMPT[:60] not in blob and "rules_your_answer_must_follow" not in blob


@pytest.mark.parametrize("text", [
    "Run aws iam detach-user-policy --user-name alice to fix it.",
    "sudo rm -rf / then restart the service now.",
    "Fetch https://evil.example/payload and apply it to alice.",
    "DROP TABLE users; then continue with the plan.",
    "```bash\nwhoami\n```",
])
def test_commands_and_urls_in_text_are_rejected(database, tools, incident_id, text) -> None:
    err = rejected(database, tools, incident_id, answer(reason=text))
    assert err.code in ("policy_violation", "invalid_json")                      # a code fence breaks JSON extraction


def test_the_system_prompt_states_the_boundaries() -> None:
    for phrase in ("do NOT execute", "candidate_actions", "invent", "LEAST DISRUPTIVE", "no_action",
                   "requires_approval", "cite evidence", "no step-by-step private reasoning"):
        assert phrase.lower() in SYSTEM_PROMPT.lower(), phrase


def test_context_is_bounded_and_scoped(database, cloud, tools, audit_entries, incident_id) -> None:
    ctx = build_context(database, tools, incident_id)
    assert len(ctx.to_json()) <= POLICY.context.max_context_chars * 1.2
    payload = ctx.payload
    assert {"incident", "triage_summary", "investigation_summary", "compliance_summary", "assets", "evidence",
            "candidate_actions", "not_available", "policy", "allowed", "rules_your_answer_must_follow"} <= set(payload)
    assert {c["action"] for c in payload["candidate_actions"]} <= ACTION_TOOL_NAMES
    tiny = policy_with(context={"max_evidence_items": 5, "max_string_length": 40, "max_context_chars": 2000})
    small = build_context(database, tools, incident_id, tiny)
    assert len(small.payload["evidence"]) <= 12 and len(small.to_json()) < len(ctx.to_json())
    assert all(i in small.evidence_ids for c in small.analysis.candidates[:1] for i in c.evidence_ids[:1])


# ===================================================================================== incident
def test_earlier_stages_are_preserved(database, cloud, tools, audit_entries, incident_id) -> None:
    before = load(database, incident_id)
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    after_plan = load(database, incident_id)
    make_executor(database, tools, audit_entries).approve(approval.approval_id)
    after_exec = load(database, incident_id)
    for later in (after_plan, after_exec):
        assert later.triage == before.triage and later.investigation == before.investigation
        assert later.compliance == before.compliance
        assert later.normalized_event == before.normalized_event and later.related_event_ids == before.related_event_ids
        assert later.verification_result is None
    assert before.remediation is None


def test_remediation_state_is_stored(database, tools, audit_entries, incident_id) -> None:
    report = proposed(database, tools, audit_entries, incident_id)
    r = load(database, incident_id).remediation
    assert r.run_id == report.run_id and r.method == RemediationMethod.LLM and r.provider == "mock"
    assert r.confidence == 0.9 and r.plan.action == RemediationAction.REMOVE_ADMIN_PRIVILEGES
    assert r.approval.status == ApprovalState.PENDING and r.execution.status == ExecutionStatus.PENDING_APPROVAL
    assert r.before_state["admin"] is True and r.after_state is None
    assert {e.evidence_id for e in r.evidence} == {"EV3", "AS1", "CS1"}
    assert r.unknowns and r.recommendations and r.based_on_compliance_run == load(database, incident_id).compliance.run_id
    assert r.plan.state_fingerprint and r.plan.proposal_hash and r.plan.rollback_available is False
    assert "no rollback tool" in r.plan.rollback_description.lower()


def test_lifecycle_statuses(database, cloud, tools, audit_entries, incident_id) -> None:
    executor = make_executor(database, tools, audit_entries)
    seen = [load(database, incident_id).final_status]                             # compliance_assessed
    first = proposed(database, tools, audit_entries, incident_id).approval
    seen.append(load(database, incident_id).final_status)                         # remediation_pending
    executor.reject(first.approval_id)
    seen.append(load(database, incident_id).final_status)                         # remediation_rejected
    second = proposed(database, tools, audit_entries, incident_id).approval
    assert executor.approve(second.approval_id).outcome == "actions_disabled"
    seen.append(load(database, incident_id).final_status)                         # remediation_approved
    enable_actions(tools)
    executor.execute(second.approval_id)
    seen.append(load(database, incident_id).final_status)                         # remediated
    assert seen == [IncidentStatus.COMPLIANCE_ASSESSED, IncidentStatus.REMEDIATION_PENDING,
                    IncidentStatus.REMEDIATION_REJECTED, IncidentStatus.REMEDIATION_APPROVED, IncidentStatus.REMEDIATED]


def test_legacy_approval_fields_stay_consistent(database, cloud, tools, audit_entries, incident_id) -> None:
    approval = proposed(database, tools, audit_entries, incident_id).approval
    incident = load(database, incident_id)
    assert incident.approval_required is True and incident.approval_status == ApprovalStatus.PENDING
    make_executor(database, tools, audit_entries).reject(approval.approval_id)
    assert load(database, incident_id).approval_status == ApprovalStatus.REJECTED


def test_compliance_is_required(database, cloud, tools, audit_entries) -> None:
    incident_id = make_investigated(database, cloud, tools, audit_entries)        # investigated, NOT compliance-assessed
    provider = MockLLMProvider([answer()])
    report = plan(make_agent(database, tools, audit_entries, provider), incident_id)
    assert report.status == AgentRunStatus.SKIPPED and report.outcome == "compliance_required"
    assert provider.calls == [] and load(database, incident_id).compliance is None    # Compliance was NOT run for it
    assert load(database, incident_id).remediation is None


def test_stale_compliance_is_a_controlled_skip(database, cloud, tools, audit_entries, incident_id) -> None:
    """Re-investigating leaves the older compliance assessment stale: remediation must not plan from it."""
    again = investigate(make_investigator(database, tools, audit_entries, MockLLMProvider([investigation_answer()])),
                        incident_id)
    assert again.status == AgentRunStatus.SUCCESS
    incident = load(database, incident_id)
    assert incident.compliance is not None and incident.final_status == IncidentStatus.INVESTIGATED
    provider = MockLLMProvider([answer()])
    report = plan(make_agent(database, tools, audit_entries, provider), incident_id)
    assert report.status == AgentRunStatus.SKIPPED and report.outcome == "compliance_required"
    assert "predates the latest investigation" in report.validation_errors[0]
    assert provider.calls == [] and load(database, incident_id).remediation is None and report.approval is None


def test_agent_runs_are_recorded(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    executor = make_executor(database, tools, audit_entries)
    plan(make_agent(database, tools, audit_entries, MockLLMProvider(available=False)), incident_id)      # failed plan
    first = proposed(database, tools, audit_entries, incident_id).approval
    executor.reject(first.approval_id)                                                                    # rejected
    second = proposed(database, tools, audit_entries, incident_id).approval
    executor.approve(second.approval_id)                                                                  # executed
    with database.session() as session:
        stats = AgentRunService(session).stats("Remediation Agent")
    assert stats["runs"] == 5 and stats["failed_runs"] == 1 and stats["successful_runs"] == 4
    assert stats["last_incident_id"] == incident_id and stats["last_result"]["outcome"] == "action_executed"
    actions = {e.action for e in audit_entries}
    assert {"remediation.run", "remediation.proposed", "remediation.approval_requested", "remediation.approved",
            "remediation.rejected", "remediation.executed", "remediation.failed"} <= actions


# ========================================================================================= API
@pytest.fixture()
def api(cloud: CloudSimulator, database: Database):
    def build(provider, actions: bool = False) -> TestClient:
        app = create_app(cloud=cloud, database=database, settings=Settings(), llm_provider=provider)
        app.state.tools.agent_actions_enabled = actions
        return TestClient(app)
    return build


def scripted(remediation=None) -> MockLLMProvider:
    return MockLLMProvider.routed({"You are the Triage Agent": [triage_answer()],
                                   "You are the Investigator Agent": [investigation_answer()],
                                   "You are the Compliance Agent": [compliance_answer()],
                                   "You are the Remediation Agent": [remediation or answer()]})


def compliant_via_api(client: TestClient) -> str:
    incident_id = client.post("/api/simulation/run",
                              json={"scenario": "iam_privilege_escalation", "run_monitor": True}).json()["incident_id"]
    for agent in ("triage", "investigator", "compliance"):
        assert client.post(f"/api/agents/{agent}/run", json={"incident_id": incident_id}).json()["status"] == "success"
    return incident_id


def test_api_successful_planning(api, cloud) -> None:
    with api(scripted()) as client:
        incident_id = compliant_via_api(client)
        response = client.post("/api/agents/remediation/run", json={"incident_id": incident_id})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "success" and body["outcome"] == "remediation_proposed"
        assert body["agent_result"]["agent_name"] == "Remediation Agent" and body["approval"]["status"] == "pending"
        detail = client.get(f"/api/incidents/{incident_id}").json()
        assert detail["final_status"] == "remediation_pending" and detail["current_agent"] == "Remediation Agent"
        assert detail["triage"] and detail["investigation"] and detail["compliance"] and detail["remediation"]
        assert detail["remediation"]["plan"]["action"] == "remove_admin_privileges"
        assert cloud.get_user("alice").admin is True                                # the run itself changed nothing


def test_api_missing_incident_is_404(api) -> None:
    with api(scripted()) as client:
        assert client.post("/api/agents/remediation/run", json={"incident_id": "INC-NOPE"}).status_code == 404


def test_api_missing_compliance_is_a_controlled_skip(api) -> None:
    with api(scripted()) as client:
        incident_id = client.post("/api/simulation/run",
                                  json={"scenario": "iam_privilege_escalation", "run_monitor": True}).json()["incident_id"]
        body = client.post("/api/agents/remediation/run", json={"incident_id": incident_id}).json()
        assert body["status"] == "skipped" and body["outcome"] == "compliance_required" and body["approval"] is None
        detail = client.get(f"/api/incidents/{incident_id}").json()
        assert detail["compliance"] is None and detail["remediation"] is None      # Compliance was not run for us


def test_api_unknown_fields_are_422(api) -> None:
    with api(scripted()) as client:
        assert client.post("/api/agents/remediation/run",
                           json={"incident_id": "INC-1", "action": "isolate_instance"}).status_code == 422
        assert client.post("/api/agents/remediation/run", json={}).status_code == 422


def test_api_approval_flow_executes(api, cloud) -> None:
    with api(scripted(), actions=True) as client:
        incident_id = compliant_via_api(client)
        run = client.post("/api/agents/remediation/run", json={"incident_id": incident_id}).json()
        approval_id = run["approval"]["approval_id"]
        pending = client.get("/api/approvals", params={"status": "pending"}).json()
        assert [a["approval_id"] for a in pending] == [approval_id]
        assert client.get(f"/api/approvals/{approval_id}").json()["target"] == "IAMUser/alice"
        agents = client.get("/api/agents").json()
        assert agents[4]["stats"]["pending_approvals"] == 1 and agents[4]["stats"]["executed_actions"] == 0
        assert cloud.get_user("alice").admin is True
        response = client.post(f"/api/approvals/{approval_id}/approve", json={"comment": "confirmed with the owner"})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["outcome"] == "executed" and body["execution"]["after_state"]["admin"] is False
        assert body["incident_status"] == "remediated" and cloud.get_user("alice").admin is False
        detail = client.get(f"/api/incidents/{incident_id}").json()
        assert detail["remediation"]["execution"]["status"] == "executed" and detail["final_status"] == "remediated"
        assert client.get("/api/approvals", params={"status": "pending"}).json() == []
        agents = client.get("/api/agents").json()
        assert agents[4]["stats"]["executed_actions"] == 1 and agents[4]["stats"]["pending_approvals"] == 0
        audit = {e["action"] for e in client.get("/api/audit").json()}
        assert {"remediation.run", "remediation.proposed", "remediation.approval_requested", "remediation.approved",
                "remediation.executed", "tool:remove_admin_privileges"} <= audit
        assert client.post(f"/api/approvals/{approval_id}/approve").status_code == 409   # cannot approve twice


def test_api_rejection_flow(api, cloud) -> None:
    with api(scripted(), actions=True) as client:
        incident_id = compliant_via_api(client)
        approval_id = client.post("/api/agents/remediation/run", json={"incident_id": incident_id}).json()["approval"]["approval_id"]
        body = client.post(f"/api/approvals/{approval_id}/reject", json={"comment": "false alarm"}).json()
        assert body["outcome"] == "rejected" and body["approval"]["status"] == "rejected"
        assert client.get(f"/api/incidents/{incident_id}").json()["final_status"] == "remediation_rejected"
        assert cloud.get_user("alice").admin is True
        assert client.post(f"/api/approvals/{approval_id}/reject").status_code == 409
        assert client.post(f"/api/approvals/{approval_id}/approve").status_code == 409
        assert client.post("/api/approvals/APR-NOPE/approve").status_code == 404
        assert client.post("/api/approvals/APR-NOPE/reject").status_code == 404


def test_api_execution_endpoint(api, cloud) -> None:
    with api(scripted(), actions=False) as client:
        incident_id = compliant_via_api(client)
        approval_id = client.post("/api/agents/remediation/run", json={"incident_id": incident_id}).json()["approval"]["approval_id"]
        assert client.post(f"/api/approvals/{approval_id}/execute").status_code == 409     # not approved yet
        blocked = client.post(f"/api/approvals/{approval_id}/approve").json()
        assert blocked["outcome"] == "actions_disabled" and blocked["execution"]["status"] == "blocked"
        assert cloud.get_user("alice").admin is True
        client.app.state.tools.agent_actions_enabled = True                          # the operator flips the kill switch
        done = client.post(f"/api/approvals/{approval_id}/execute").json()
        assert done["outcome"] == "executed" and cloud.get_user("alice").admin is False


def test_api_decision_bodies_cannot_carry_an_action(api) -> None:
    with api(scripted(), actions=True) as client:
        incident_id = compliant_via_api(client)
        approval_id = client.post("/api/agents/remediation/run", json={"incident_id": incident_id}).json()["approval"]["approval_id"]
        for body in ({"action": "disable_access_key"}, {"target": "IAMUser/bob"}, {"arguments": {"username": "bob"}}):
            assert client.post(f"/api/approvals/{approval_id}/approve", json=body).status_code == 422
        assert client.get(f"/api/approvals/{approval_id}").json()["status"] == "pending"


def test_api_remediation_is_503_without_its_policy(cloud, database, tmp_path) -> None:
    for name in ("monitor_rules.yaml", "triage_rules.yaml", "investigator_rules.yaml"):
        (tmp_path / name).write_text((CONFIG_DIR / name).read_text(encoding="utf-8"), encoding="utf-8")
    settings = Settings(config_dir=tmp_path)
    with TestClient(create_app(cloud=cloud, database=database, settings=settings, llm_provider=None)) as client:
        assert client.post("/api/agents/remediation/run", json={"incident_id": "INC-1"}).status_code in (404, 503)
        assert client.post("/api/approvals/APR-1/approve").status_code == 503


def test_api_agents_endpoint_lists_remediation(api) -> None:
    with api(scripted()) as client:
        remediation = client.get("/api/agents").json()[4]
        assert remediation["implemented"] is True and remediation["status"] == "idle"
        assert remediation["llm"]["provider"] == "mock" and "isolate_instance" in remediation["tools"]
        tools = client.get("/api/tools").json()
        assert tools["agent_actions_enabled"] is False
        assert client.get("/api/approvals").json() == []
