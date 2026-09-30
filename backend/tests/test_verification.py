"""Verification Agent tests. Verification is deterministic: there is no LLM in it (the LLM only appears to
plan the remediation that gets verified). It must read the ACTUAL state, never trust "executed"."""

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.agents.verification.agent import VerificationAgent, VerificationRunRequest
from app.agents.verification.comparison import classify, compare
from app.agents.verification.config import VerificationConfigError, VerificationRules, load_verification_rules
from app.config import Settings
from app.database.connection import Database
from app.database.models import ApprovalRecord
from app.domain.enums import AgentName, AgentRunStatus, ApprovalStatus, IncidentStatus, VerificationStatus as LegacyStatus
from app.domain.remediation import ExecutionStatus
from app.domain.verification import VerificationMethod, VerificationStatus
from app.llm.mock import MockLLMProvider
from app.main import create_app
from app.services.agent_runs import AgentRunService
from app.simulator.cloud import CloudSimulator, ResourceNotFoundError
from app.tools.base import ApprovalGrant, ToolRequest
from app.tools.registry import ACTION_TOOL_NAMES
from tests.test_remediation import (  # noqa: F401  (fixtures + helpers reused from Phase 6)
    POLICY,
    answer,
    audit_entries,
    compliant_via_api,
    enable_actions,
    incident_id,
    load,
    make_agent,
    make_compliant,
    make_executor,
    plan,
    proposed,
    scripted,
    tool_audits,
    tools,
)

CONFIG_DIR = Settings().config_dir
RULES = load_verification_rules(CONFIG_DIR)
BACKEND = Path(__file__).resolve().parent.parent
VERIFICATION_SRC = BACKEND / "app" / "agents" / "verification"


# ============================================================================ builders
def make_verifier(database, tools, audit_entries, rules=RULES) -> VerificationAgent:
    return VerificationAgent(database, rules, tools, audit_sink=audit_entries.append)


def verify(agent: VerificationAgent, incident_id: str):
    return agent.run(VerificationRunRequest(incident_id=incident_id))


def remediate(database, cloud, tools, audit_entries, incident_id, **overrides) -> str:
    """Plan (mock LLM) -> human approves -> ToolExecutor executes. Returns the approval id."""
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id, **overrides).approval
    report = make_executor(database, tools, audit_entries).approve(approval.approval_id)
    assert report.outcome == "executed", report.message
    return approval.approval_id


def rules_with(**changes) -> VerificationRules:
    data = RULES.model_dump(mode="json")
    data["verification"].update(changes)
    return VerificationRules.model_validate(data)


# ============================================================================== verified
def test_successful_verification(database, cloud, tools, audit_entries, incident_id) -> None:
    assert cloud.get_user("alice").admin is True
    remediate(database, cloud, tools, audit_entries, incident_id)
    report = verify(make_verifier(database, tools, audit_entries), incident_id)
    assert report.status == AgentRunStatus.SUCCESS and report.outcome == "verified"
    v = report.verification
    assert v.status == VerificationStatus.VERIFIED and v.method == VerificationMethod.DETERMINISTIC
    assert (v.action.value, v.target, v.expected_state) == ("remove_admin_privileges", "IAMUser/alice", {"admin": False})
    [row] = v.comparison
    assert (row.field, row.before, row.expected, row.actual, row.satisfied, row.changed_from_before) == \
        ("admin", True, False, False, True, True)
    assert v.actual_state["admin"] is False and v.before_state["admin"] is True and v.confidence == 1.0
    assert v.failure_reason is None and "achieved its expected security effect" in v.reason
    assert v.reported_execution_status == ExecutionStatus.EXECUTED and v.recommendations == ["close_incident_after_human_review"]
    incident = load(database, incident_id)
    assert incident.final_status == IncidentStatus.VERIFIED and incident.current_agent == AgentName.VERIFICATION
    assert incident.verification.run_id == report.run_id
    assert incident.verification_result.status == LegacyStatus.VERIFIED           # legacy field kept consistent
    assert [d.actor for d in incident.agent_decisions].count(AgentName.VERIFICATION) == 1


def test_verification_evidence_is_backend_generated(database, cloud, tools, audit_entries, incident_id) -> None:
    remediate(database, cloud, tools, audit_entries, incident_id)
    v = verify(make_verifier(database, tools, audit_entries), incident_id).verification
    by_id = {e.evidence_id: e for e in v.evidence}
    assert [e.type for e in v.evidence] == ["before_state", "expected_state", "actual_state", "execution_status"]
    assert set(by_id) == {"VER1", "VER2", "VER3", "VER4"}
    assert by_id["VER1"].data["admin"] is True and by_id["VER2"].data == {"admin": False}
    assert by_id["VER3"].data["admin"] is False and by_id["VER4"].data["execution_status"] == "executed"
    assert "NOT trusted" in by_id["VER4"].source


def test_earlier_stages_are_preserved(database, cloud, tools, audit_entries, incident_id) -> None:
    before = load(database, incident_id)
    remediate(database, cloud, tools, audit_entries, incident_id)
    remediation = load(database, incident_id).remediation
    verify(make_verifier(database, tools, audit_entries), incident_id)
    after = load(database, incident_id)
    assert after.triage == before.triage and after.investigation == before.investigation
    assert after.compliance == before.compliance and after.remediation == remediation
    assert after.normalized_event == before.normalized_event


# =================================================================================== failed
def test_success_reported_but_state_unchanged_is_failed(database, cloud, tools, audit_entries, incident_id) -> None:
    """The remediation said 'executed' (and its own read-back agreed); the state then regressed."""
    remediate(database, cloud, tools, audit_entries, incident_id)
    assert load(database, incident_id).remediation.execution.status == ExecutionStatus.EXECUTED
    cloud.make_user_admin("alice")                                            # admin is true again
    report = verify(make_verifier(database, tools, audit_entries), incident_id)
    v = report.verification
    assert v.status == VerificationStatus.FAILED and report.outcome == "verification_failed"
    assert v.reported_execution_status == ExecutionStatus.EXECUTED             # claimed success, NOT trusted
    assert v.failure_reason == "expected_state_not_achieved" and v.confidence == RULES.confidence.failed
    assert (v.comparison[0].expected, v.comparison[0].actual, v.comparison[0].satisfied) == (False, True, False)
    assert "intended security state was not achieved" in v.reason
    assert v.recommendations == ["reassess_remediation", "keep_incident_open"]
    incident = load(database, incident_id)
    assert incident.final_status == IncidentStatus.VERIFICATION_FAILED          # incident stays open
    assert incident.verification_result.status == LegacyStatus.FAILED
    assert cloud.get_user("alice").admin is True                               # and it was NOT remediated again
    assert len(tool_audits(audit_entries, "remove_admin_privileges")) == 1


def test_failed_verification_does_not_retry_remediation(database, cloud, tools, audit_entries, incident_id) -> None:
    approval_id = remediate(database, cloud, tools, audit_entries, incident_id)
    cloud.make_user_admin("alice")
    verify(make_verifier(database, tools, audit_entries), incident_id)
    with database.session() as session:
        assert session.query(ApprovalRecord).count() == 1                       # no new approval was requested
    assert len(tool_audits(audit_entries, "remove_admin_privileges")) == 1      # no second execution
    assert approval_id and "remediation.run" not in [e.action for e in audit_entries if e.action == "verification.run"]


def test_failed_execution_is_failed_not_success(database, cloud, tools, audit_entries, incident_id, monkeypatch) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval

    def boom(_name):
        raise RuntimeError("simulated outage")

    monkeypatch.setattr(cloud, "remove_admin_privileges", boom)
    assert make_executor(database, tools, audit_entries).approve(approval.approval_id).execution.status == ExecutionStatus.FAILED
    v = verify(make_verifier(database, tools, audit_entries), incident_id).verification
    assert v.status == VerificationStatus.FAILED and v.failure_reason == "remediation_execution_failed"
    assert v.confidence == RULES.confidence.execution_failed and v.reported_execution_status == ExecutionStatus.FAILED
    assert "execution failed" in v.reason and v.actual_state["admin"] is True
    assert load(database, incident_id).final_status == IncidentStatus.VERIFICATION_FAILED


# ================================================================================== partial
def test_partial_verification(database, cloud, tools, audit_entries, incident_id) -> None:
    rules = rules_with(remove_admin_privileges={
        "resource_type": "IAMUser", "description": "no admin and no active keys",
        "required_state": {"admin": False, "access_key_active": False}})
    remediate(database, cloud, tools, audit_entries, incident_id)             # admin removed, keys still active
    report = verify(make_verifier(database, tools, audit_entries, rules), incident_id)
    v = report.verification
    assert v.status == VerificationStatus.PARTIAL and report.status == AgentRunStatus.PARTIAL
    assert report.outcome == "verification_partial" and v.confidence == RULES.confidence.partial
    assert {r.field: r.satisfied for r in v.comparison} == {"admin": True, "access_key_active": False}
    assert v.failure_reason == "expected_state_partially_achieved" and "access_key_active" in v.reason
    assert load(database, incident_id).final_status == IncidentStatus.PARTIAL_REMEDIATION
    assert "review_remaining_exposure" in v.recommendations


# =================================================================================== unknown
def test_unavailable_state_is_unknown_not_success(database, cloud, tools, audit_entries, incident_id, monkeypatch) -> None:
    remediate(database, cloud, tools, audit_entries, incident_id)

    def gone(_name):
        raise ResourceNotFoundError("IAM user 'alice' not found")

    monkeypatch.setattr(cloud, "get_user", gone)
    report = verify(make_verifier(database, tools, audit_entries), incident_id)
    v = report.verification
    assert v.status == VerificationStatus.UNKNOWN and v.failure_reason == "state_unavailable"
    assert v.actual_state is None and v.comparison == [] and v.confidence == RULES.confidence.unknown
    assert load(database, incident_id).final_status == IncidentStatus.VERIFICATION_UNKNOWN
    assert load(database, incident_id).verification_result.status == LegacyStatus.NOT_VERIFIED


def test_incomplete_state_is_unknown(database, cloud, tools, audit_entries, incident_id) -> None:
    rules = rules_with(remove_admin_privileges={"resource_type": "IAMUser", "description": "x",
                                                "required_state": {"no_such_field": False}})
    remediate(database, cloud, tools, audit_entries, incident_id)
    v = verify(make_verifier(database, tools, audit_entries, rules), incident_id).verification
    assert v.status == VerificationStatus.UNKNOWN and v.failure_reason == "state_incomplete"


def test_comparison_is_exact_not_truthy() -> None:
    rows = compare({"admin": True}, {"admin": False}, {"admin": 0})           # 0 == False in Python, but not the same value
    assert rows[0].satisfied is False and classify(rows) == VerificationStatus.FAILED
    assert classify([]) == VerificationStatus.UNKNOWN


# ================================================================================== skipped
def test_pending_remediation_is_skipped(database, cloud, tools, audit_entries, incident_id) -> None:
    proposed(database, tools, audit_entries, incident_id)                     # pending approval
    before = load(database, incident_id)
    report = verify(make_verifier(database, tools, audit_entries), incident_id)
    assert report.status == AgentRunStatus.SKIPPED and report.outcome == "remediation_not_ready"
    assert report.verification is None and load(database, incident_id) == before
    assert "verification.skipped" in [e.action for e in audit_entries]


def test_approved_but_blocked_remediation_is_skipped(database, cloud, tools, audit_entries, incident_id) -> None:
    approval = proposed(database, tools, audit_entries, incident_id).approval  # kill switch off (default)
    assert make_executor(database, tools, audit_entries).approve(approval.approval_id).outcome == "actions_disabled"
    report = verify(make_verifier(database, tools, audit_entries), incident_id)
    assert report.status == AgentRunStatus.SKIPPED and report.outcome == "remediation_not_executed"
    assert cloud.get_user("alice").admin is True


def test_rejected_remediation_is_skipped(database, cloud, tools, audit_entries, incident_id) -> None:
    approval = proposed(database, tools, audit_entries, incident_id).approval
    make_executor(database, tools, audit_entries).reject(approval.approval_id)
    report = verify(make_verifier(database, tools, audit_entries), incident_id)
    assert report.status == AgentRunStatus.SKIPPED and report.outcome == "remediation_not_executed"
    assert load(database, incident_id).verification is None


def test_no_remediation_and_no_action_are_skipped(database, cloud, tools, audit_entries, incident_id) -> None:
    assert verify(make_verifier(database, tools, audit_entries), incident_id).outcome == "remediation_not_ready"
    proposed(database, tools, audit_entries, incident_id, action="no_action", target=None, evidence_ids=[],
             reason="A human should decide before any action is chosen here.", expected_effect="No change.",
             risk_level="info", requires_approval=False)
    assert verify(make_verifier(database, tools, audit_entries), incident_id).outcome == "remediation_not_executed"


# ================================================================================ idempotency
def test_repeated_verification_is_read_only(database, cloud, tools, audit_entries, incident_id) -> None:
    remediate(database, cloud, tools, audit_entries, incident_id)
    verifier = make_verifier(database, tools, audit_entries)
    first = verify(verifier, incident_id)
    state, remediation = cloud.get_cloud_state(), load(database, incident_id).remediation
    second = verify(verifier, incident_id)
    assert first.verification.status == second.verification.status == VerificationStatus.VERIFIED
    assert cloud.get_cloud_state() == state and load(database, incident_id).remediation == remediation
    assert len(tool_audits(audit_entries, "remove_admin_privileges")) == 1
    incident = load(database, incident_id)
    assert incident.verification.run_id == second.run_id != first.run_id       # latest replaces, history is kept
    assert [d.actor for d in incident.agent_decisions].count(AgentName.VERIFICATION) == 1
    with database.session() as session:
        stats = AgentRunService(session).stats(AgentName.VERIFICATION.value)
    assert stats["runs"] == 2 and stats["successful_runs"] == 2 and stats["last_incident_id"] == incident_id
    with database.session() as session:
        assert session.query(ApprovalRecord).count() == 1


def test_reverification_follows_the_current_state(database, cloud, tools, audit_entries, incident_id) -> None:
    remediate(database, cloud, tools, audit_entries, incident_id)
    verifier = make_verifier(database, tools, audit_entries)
    assert verify(verifier, incident_id).verification.status == VerificationStatus.VERIFIED
    cloud.make_user_admin("alice")
    assert verify(verifier, incident_id).verification.status == VerificationStatus.FAILED
    cloud.remove_admin_privileges("alice")                                    # fixed by someone else
    assert verify(verifier, incident_id).verification.status == VerificationStatus.VERIFIED


def test_a_failed_verification_allows_a_new_human_triggered_remediation(database, cloud, tools, audit_entries, incident_id) -> None:
    remediate(database, cloud, tools, audit_entries, incident_id)
    cloud.make_user_admin("alice")
    verify(make_verifier(database, tools, audit_entries), incident_id)
    report = plan(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    assert report.status == AgentRunStatus.SUCCESS and report.approval is not None       # a human still has to approve
    incident = load(database, incident_id)
    assert incident.final_status == IncidentStatus.REMEDIATION_PENDING
    assert incident.verification.based_on_remediation_run != incident.remediation.run_id     # the old verification is stale
    assert verify(make_verifier(database, tools, audit_entries), incident_id).outcome == "remediation_not_ready"


# ============================================================================ all four actions
CASES = {
    "remove_admin_privileges": ("iam_privilege_escalation", {}, lambda c: c.make_user_admin("alice")),
    "disable_access_key": ("iam_privilege_escalation", dict(
        action="disable_access_key", target="IAMUser/alice", risk_level="high",
        reason="alice's access keys were used from an untrusted IP after privilege escalation.",
        expected_effect="alice's access keys are deactivated."), lambda c: c.enable_access_key("alice")),
    "isolate_instance": ("ec2_compromise", dict(
        action="isolate_instance", target="EC2Instance/ec2-001", risk_level="high", evidence_ids=["CS1"],
        reason="ec2-001 ran attacker commands and generated abnormal outbound traffic.",
        expected_effect="ec2-001 is quarantined."), lambda c: c.restore_instance("ec2-001")),
    "make_bucket_private": ("public_s3_exposure", dict(
        action="make_bucket_private", target="S3Bucket/company-data", evidence_ids=["CS1"],
        reason="company-data was made public and a sensitive object was downloaded.",
        expected_effect="company-data no longer allows public access."), lambda c: c.make_bucket_public("company-data")),
}


@pytest.mark.parametrize("action", list(CASES))
def test_all_four_actions_verified_and_failed(database, cloud, tools, audit_entries, action) -> None:
    scenario, overrides, undo = CASES[action]
    incident_id = make_compliant(database, cloud, tools, audit_entries, scenario)
    remediate(database, cloud, tools, audit_entries, incident_id, **overrides)
    verifier = make_verifier(database, tools, audit_entries)
    good = verify(verifier, incident_id).verification
    assert good.status == VerificationStatus.VERIFIED and good.action.value == action, good.reason
    assert good.expected_state == RULES.verification[action].required_state
    assert all(r.satisfied and r.changed_from_before for r in good.comparison)
    undo(cloud)                                                                # the change is reverted behind its back
    bad = verify(verifier, incident_id).verification
    assert bad.status == VerificationStatus.FAILED and not any(r.satisfied for r in bad.comparison)
    assert bad.reported_execution_status == ExecutionStatus.EXECUTED


# =================================================================================== security
def test_verification_has_no_action_tool_permission(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)                                                      # even with the kill switch ON
    approval = proposed(database, tools, audit_entries, incident_id).approval
    grant = ApprovalGrant(approval_id=approval.approval_id, incident_id=incident_id, tool_name="remove_admin_privileges",
                          status=ApprovalStatus.APPROVED, decided_by="Human Analyst")
    args = {"remove_admin_privileges": {"username": "alice"}, "disable_access_key": {"username": "alice"},
            "isolate_instance": {"instance_id": "ec2-001"}, "make_bucket_private": {"bucket_name": "public-assets"}}
    state = cloud.get_cloud_state()
    for tool in sorted(ACTION_TOOL_NAMES):
        result = tools.execute(ToolRequest(tool_name=tool, arguments=args[tool], requested_by=AgentName.VERIFICATION,
                                           incident_id=incident_id, approval=grant.model_copy(update={"tool_name": tool})))
        assert result.error_code == "permission_denied", tool
    assert cloud.get_cloud_state() == state
    granted = set(tools.registry.permissions_for(AgentName.VERIFICATION))
    assert not granted & ACTION_TOOL_NAMES
    assert granted == {"get_incident", "get_resource", "get_iam_entity", "get_cloudtrail_events", "get_security_findings",
                       "get_network_events", "get_asset_context", "check_policy"}


def test_verification_cannot_modify_state_approve_or_bypass_the_kill_switch(database, cloud, tools, audit_entries, incident_id) -> None:
    remediate(database, cloud, tools, audit_entries, incident_id)
    enable_actions(tools, False)                                               # kill switch off after the fact
    state = cloud.get_cloud_state()
    with database.session() as session:
        approvals = [(a.approval_id, a.status, a.reviewed_at) for a in session.query(ApprovalRecord).all()]
    verify(make_verifier(database, tools, audit_entries), incident_id)
    assert cloud.get_cloud_state() == state and tools.registry.agent_actions_enabled is False
    with database.session() as session:
        assert [(a.approval_id, a.status, a.reviewed_at) for a in session.query(ApprovalRecord).all()] == approvals
    assert not [e for e in audit_entries if e.actor == AgentName.VERIFICATION and e.action.startswith("tool:")]


def test_verification_code_is_read_only_by_construction() -> None:
    for path in VERIFICATION_SRC.glob("*.py"):
        code = "\n".join(l for l in path.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith(("#", '"""')))
        assert not re.search(r"^\s*(from|import)\s+app\.simulator", code, re.M), path.name
        assert not re.search(r"^\s*(from|import)\s+app\.(llm|services\.approvals)", code, re.M), path.name
        assert not re.search(r"remediation\.(execution|agent)|RemediationExecutor|ApprovalService", code), path.name
        assert not re.search(r"^\s*(from|import)\s+(httpx|requests|urllib|socket|subprocess)", code, re.M), path.name
        assert not re.search(r"\b(subprocess|os\.system|eval|exec)\b|\.cloud\.|CloudSimulator", code), path.name
        for name in ACTION_TOOL_NAMES:
            assert f'"{name}"' not in code or path.name in ("config.py",), (path.name, name)
        for tool in re.findall(r'tool_name\s*=\s*"([a-z_]+)"', code):
            assert tool in {"get_resource"}, (path.name, tool)


def test_verification_takes_no_llm() -> None:
    import inspect
    params = set(inspect.signature(VerificationAgent.__init__).parameters)
    assert not params & {"provider", "llm", "llm_provider"}
    assert VerificationMethod.DETERMINISTIC.value == "deterministic"


def test_confidence_is_computed_not_copied(database, cloud, tools, audit_entries, incident_id) -> None:
    remediate(database, cloud, tools, audit_entries, incident_id, confidence=0.31)
    incident = load(database, incident_id)
    assert incident.remediation.confidence == 0.31
    v = verify(make_verifier(database, tools, audit_entries), incident_id).verification
    assert v.confidence == RULES.confidence.verified == 1.0
    assert v.confidence not in {incident.confidence, incident.triage.confidence, incident.investigation.confidence,
                                incident.compliance.confidence, incident.remediation.confidence}
    cloud.make_user_admin("alice")
    assert verify(make_verifier(database, tools, audit_entries), incident_id).verification.confidence == RULES.confidence.failed


def test_no_secrets_in_verification_output_or_audit(database, cloud, tools, audit_entries, incident_id) -> None:
    keys = [k.key_id for k in cloud.get_user("alice").access_keys]
    remediate(database, cloud, tools, audit_entries, incident_id)
    keys += [k.key_id for k in cloud.get_user("alice").access_keys]
    report = verify(make_verifier(database, tools, audit_entries), incident_id)
    blob = json.dumps(report.model_dump(mode="json"), default=str)
    blob += json.dumps([e.model_dump(mode="json") for e in audit_entries if e.action.startswith("verification.")], default=str)
    blob += json.dumps(load(database, incident_id).verification.model_dump(mode="json"), default=str)
    assert keys and not any(k in blob for k in keys) and not re.search(r"AKIA[A-Z0-9]{6,}", blob)


def test_no_raw_model_output_or_prompts_in_verification_audit(database, cloud, tools, audit_entries, incident_id) -> None:
    remediate(database, cloud, tools, audit_entries, incident_id)
    provider = MockLLMProvider([answer()])
    verify(make_verifier(database, tools, audit_entries), incident_id)
    assert provider.calls == []                                                # nothing here can even call a model
    blob = json.dumps([e.model_dump(mode="json") for e in audit_entries if e.action.startswith("verification.")], default=str)
    assert "rules_your_answer_must_follow" not in blob and "You are the" not in blob


# ==================================================================== audit / runs / lifecycle
def test_audit_and_run_history(database, cloud, tools, audit_entries, incident_id) -> None:
    verifier = make_verifier(database, tools, audit_entries)
    proposed(database, tools, audit_entries, incident_id)
    verify(verifier, incident_id)                                              # skipped (pending)
    approval = load(database, incident_id).remediation.approval
    enable_actions(tools)
    make_executor(database, tools, audit_entries).approve(approval.approval_id)
    verify(verifier, incident_id)                                              # verified
    cloud.make_user_admin("alice")
    verify(verifier, incident_id)                                              # failed
    actions = [e.action for e in audit_entries if e.action.startswith("verification.")]
    assert actions.count("verification.run") == 3
    assert {"verification.skipped", "verification.completed", "verification.failed"} <= set(actions)
    done = next(e for e in audit_entries if e.action == "verification.completed")
    assert done.actor == AgentName.VERIFICATION and done.details["verification_status"] == "verified"
    assert done.details["action"] == "remove_admin_privileges" and done.details["target"] == "IAMUser/alice"
    assert done.details["expected_state"] == {"admin": False} and done.details["actual_state"]["admin"] is False
    assert done.details["method"] == "deterministic" and done.details["confidence"] == 1.0
    with database.session() as session:
        stats = AgentRunService(session).stats(AgentName.VERIFICATION.value)
    assert stats["runs"] == 3 and stats["successful_runs"] == 2 and stats["last_result"]["outcome"] == "verification_failed"


# ======================================================================================= config
def test_rules_match_the_simulator_and_the_remediation_policy() -> None:
    assert set(RULES.verification) == set(ACTION_TOOL_NAMES)
    for name, rule in RULES.verification.items():
        policy = POLICY.actions[name]
        assert rule.required_state == policy.postcondition, name              # one truth for "the desired state"
        assert rule.resource_type == policy.resource_type, name
    sim = CloudSimulator()
    assert hasattr(sim.get_user("alice"), "admin") and hasattr(sim.get_user("alice"), "access_key_active")
    assert sim.get_instance("ec2-001").status in ("running", "isolated") and hasattr(sim.get_bucket("company-data"), "public_access")


def test_rules_file_is_validated(tmp_path) -> None:
    good = (CONFIG_DIR / "verification_rules.yaml").read_text(encoding="utf-8")
    (tmp_path / "verification_rules.yaml").write_text(good.replace("  make_bucket_private:", "  delete_database:", 1), encoding="utf-8")
    with pytest.raises(VerificationConfigError, match="exactly the registered action tools"):
        load_verification_rules(tmp_path)
    (tmp_path / "verification_rules.yaml").write_text(good.replace("required_state: {admin: false}", "required_state: {}", 1), encoding="utf-8")
    with pytest.raises(VerificationConfigError, match="at least one field"):
        load_verification_rules(tmp_path)
    with pytest.raises(VerificationConfigError, match="not found"):
        load_verification_rules(tmp_path / "missing")


# ========================================================================================= API
@pytest.fixture()
def api(cloud: CloudSimulator, database: Database):
    def build(provider, actions: bool = True) -> TestClient:
        app = create_app(cloud=cloud, database=database, settings=Settings(), llm_provider=provider)
        app.state.tools.agent_actions_enabled = actions
        return TestClient(app)
    return build


def test_api_end_to_end_verified_then_failed(api, cloud) -> None:
    with api(scripted()) as client:
        incident_id = compliant_via_api(client)
        skipped = client.post("/api/agents/verification/run", json={"incident_id": incident_id}).json()
        assert skipped["status"] == "skipped" and skipped["outcome"] == "remediation_not_ready" and skipped["verification"] is None
        approval_id = client.post("/api/agents/remediation/run", json={"incident_id": incident_id}).json()["approval"]["approval_id"]
        assert client.post("/api/agents/verification/run", json={"incident_id": incident_id}).json()["outcome"] == "remediation_not_ready"
        assert client.post(f"/api/approvals/{approval_id}/approve").json()["outcome"] == "executed"
        assert cloud.get_user("alice").admin is False
        body = client.post("/api/agents/verification/run", json={"incident_id": incident_id}).json()
        assert body["status"] == "success" and body["outcome"] == "verified" and body["verification_status"] == "verified"
        assert body["agent_result"]["agent_name"] == "Verification Agent"
        detail = client.get(f"/api/incidents/{incident_id}").json()
        assert detail["final_status"] == "verified" and detail["current_agent"] == "Verification Agent"
        for stage in ("triage", "investigation", "compliance", "remediation", "verification"):
            assert detail[stage]
        v = detail["verification"]
        assert v["method"] == "deterministic" and v["comparison"][0]["actual"] is False and v["evidence"][0]["evidence_id"] == "VER1"
        cloud.make_user_admin("alice")                                         # ToolExecutor said success, but...
        failed = client.post("/api/agents/verification/run", json={"incident_id": incident_id}).json()
        assert failed["verification_status"] == "failed" and failed["outcome"] == "verification_failed"
        assert client.get(f"/api/incidents/{incident_id}").json()["final_status"] == "verification_failed"
        agents = client.get("/api/agents").json()
        stats = agents[5]["stats"]
        assert agents[5]["name"] == "Verification Agent" and agents[5]["implemented"] is True
        assert (stats["runs"], stats["verified"], stats["verification_failed"], stats["skipped"]) == (4, 1, 1, 2)
        assert stats["method"] == "deterministic" and agents[5]["llm"] is None
        audit = {e["action"] for e in client.get("/api/audit").json()}
        assert {"verification.run", "verification.completed", "verification.failed", "verification.skipped"} <= audit
        assert cloud.get_user("alice").admin is True                           # verification never re-remediated


def test_api_missing_incident_is_404(api) -> None:
    with api(scripted()) as client:
        assert client.post("/api/agents/verification/run", json={"incident_id": "INC-NOPE"}).status_code == 404


@pytest.mark.parametrize("body", [{}, {"incident_id": ""}, {"incident_id": "INC-1", "action": "isolate_instance"},
                                  {"incident_id": "INC-1", "approve": True}, {"incident_id": ["INC-1"]}, {"incident_id": "a b"}])
def test_api_invalid_requests_are_422(api, body) -> None:
    with api(scripted()) as client:
        assert client.post("/api/agents/verification/run", json=body).status_code == 422


def test_api_verification_is_503_without_its_rules(cloud, database, tmp_path) -> None:
    settings = Settings(config_dir=tmp_path)
    with TestClient(create_app(cloud=cloud, database=database, settings=settings, llm_provider=None)) as client:
        assert client.post("/api/agents/verification/run", json={"incident_id": "INC-1"}).status_code in (404, 503)
