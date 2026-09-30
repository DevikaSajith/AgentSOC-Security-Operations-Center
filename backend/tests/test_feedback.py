"""Feedback & Learning (Phase 8) tests. The engine is deterministic: it classifies, analyses and RECOMMENDS.
It must never execute, approve or mutate anything."""

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.agents.feedback.config import FeedbackConfigError, FeedbackRules, load_feedback_rules
from app.agents.feedback.engine import (
    FeedbackEngine,
    FeedbackRequestError,
    FeedbackRunRequest,
    HumanFeedbackRequest,
    LearningNotFoundError,
)
from app.config import Settings
from app.database.models import ApprovalRecord
from app.domain.enums import AgentName, AgentRunStatus, ApprovalStatus, HumanActor, IncidentStatus
from app.domain.learning import FailureReason, FeedbackType, HumanFeedback, LearningRecord, Recommendation
from app.domain.remediation import ExecutionStatus, RemediationAction
from app.domain.verification import VerificationStatus
from app.llm.mock import MockLLMProvider
from app.main import create_app
from app.services.incident_service import IncidentService
from app.services.learning import LearningService
from app.simulator.cloud import CloudSimulator, ResourceNotFoundError
from app.tools.base import ApprovalGrant, ToolRequest
from app.tools.registry import ACTION_TOOL_NAMES
from tests.test_remediation import (  # noqa: F401
    audit_entries,
    compliant_via_api,
    enable_actions,
    incident_id,
    load,
    make_executor,
    plan,
    proposed,
    scripted,
    tools,
)
from tests.test_remediation import make_agent as make_remediation
from tests.test_verification import RULES, make_verifier, remediate, rules_with, verify

CONFIG_DIR = Settings().config_dir
FRULES = load_feedback_rules(CONFIG_DIR)
FEEDBACK_SRC = Path(__file__).resolve().parent.parent / "app" / "agents" / "feedback"


def make_engine(database, tools, audit_entries, vrules=RULES, rules=FRULES) -> FeedbackEngine:
    return FeedbackEngine(database, rules, vrules, tools, audit_sink=audit_entries.append)


def learn(engine: FeedbackEngine, incident_id: str):
    return engine.run(FeedbackRunRequest(incident_id=incident_id))


def verified_incident(database, cloud, tools, audit_entries, incident_id) -> None:
    remediate(database, cloud, tools, audit_entries, incident_id)
    assert verify(make_verifier(database, tools, audit_entries), incident_id).verification.status == VerificationStatus.VERIFIED


def failed_incident(database, cloud, tools, audit_entries, incident_id) -> None:
    verified_incident(database, cloud, tools, audit_entries, incident_id)
    cloud.make_user_admin("alice")                                             # regressed behind the remediation's back
    assert verify(make_verifier(database, tools, audit_entries), incident_id).verification.status == VerificationStatus.FAILED


def edit_incident(database, incident_id, **changes):
    with database.session() as session:
        service = IncidentService(session)
        incident = service.get(incident_id)
        service.save(incident.model_copy(update=changes))


# ====================================================================== outcome classification
def test_verified_becomes_a_successful_learning_record(database, cloud, tools, audit_entries, incident_id) -> None:
    verified_incident(database, cloud, tools, audit_entries, incident_id)
    report = learn(make_engine(database, tools, audit_entries), incident_id)
    assert report.status == AgentRunStatus.SUCCESS and report.outcome == "learning_created" and not report.regression_detected
    [r] = report.learning
    assert r.feedback_type == r.auto_feedback_type == FeedbackType.SUCCESSFUL_RESPONSE and r.successful is True
    assert r.failure_reason is None and r.recommendation == Recommendation.NO_FURTHER_ACTION
    assert (r.remediation_action, r.remediation_target, r.verification_status) == ("remove_admin_privileges", "IAMUser/alice", "verified")
    incident = load(database, incident_id)
    assert r.verification_run_id == incident.verification.run_id
    assert r.agent_run_ids == {"triage": incident.triage.run_id, "investigation": incident.investigation.run_id,
                               "compliance": incident.compliance.run_id, "remediation": incident.remediation.run_id,
                               "verification": incident.verification.run_id}
    assert r.incident_category == "iam" and r.initial_severity and r.final_severity == incident.severity.value
    assert r.providers["triage"].startswith("mock/")
    assert r.verification_result["expected_state"] == {"admin": False}
    actions = [e.action for e in audit_entries if e.action.startswith("learning.")]
    assert actions == ["learning.created"]


def test_failed_verification_is_analysed(database, cloud, tools, audit_entries, incident_id) -> None:
    failed_incident(database, cloud, tools, audit_entries, incident_id)
    [r] = learn(make_engine(database, tools, audit_entries), incident_id).learning
    assert r.feedback_type == FeedbackType.FAILED_RESPONSE and r.successful is False
    assert r.failure_reason == FailureReason.STATE_REGRESSION                # the remediation's own read-back was fine
    assert r.recommendation == Recommendation.RETRY_SAME_ACTION
    assert {"learning.created", "learning.failure_analyzed"} <= {e.action for e in audit_entries}
    assert cloud.get_user("alice").admin is True                              # nothing was re-remediated


def test_state_never_reached_is_expected_state_not_reached(database, cloud, tools, audit_entries, incident_id) -> None:
    failed_incident(database, cloud, tools, audit_entries, incident_id)
    incident = load(database, incident_id)
    execution = incident.remediation.execution.model_copy(update={"after_state": {"admin": True}})
    edit_incident(database, incident_id, remediation=incident.remediation.model_copy(update={"execution": execution}))
    [r] = learn(make_engine(database, tools, audit_entries), incident_id).learning
    assert r.failure_reason == FailureReason.EXPECTED_STATE_NOT_REACHED


def test_execution_failure(database, cloud, tools, audit_entries, incident_id, monkeypatch) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    monkeypatch.setattr(cloud, "remove_admin_privileges", lambda name: (_ for _ in ()).throw(RuntimeError("outage")))
    assert make_executor(database, tools, audit_entries).approve(approval.approval_id).execution.status == ExecutionStatus.FAILED
    verify(make_verifier(database, tools, audit_entries), incident_id)
    [r] = learn(make_engine(database, tools, audit_entries), incident_id).learning
    assert r.failure_reason == FailureReason.EXECUTION_FAILURE and r.feedback_type == FeedbackType.FAILED_RESPONSE


def test_wrong_target_and_wrong_action(database, cloud, tools, audit_entries, incident_id) -> None:
    failed_incident(database, cloud, tools, audit_entries, incident_id)
    v = load(database, incident_id).verification
    edit_incident(database, incident_id, verification=v.model_copy(update={"target": "IAMUser/bob"}))
    [r] = learn(make_engine(database, tools, audit_entries), incident_id).learning
    assert r.failure_reason == FailureReason.WRONG_TARGET and r.recommendation == Recommendation.REINVESTIGATE
    edit_incident(database, incident_id, verification=v.model_copy(update={
        "run_id": "VER-OTHER", "action": RemediationAction.ISOLATE_INSTANCE, "target": "IAMUser/alice"}))
    [r2] = learn(make_engine(database, tools, audit_entries), incident_id).learning
    assert r2.failure_reason == FailureReason.WRONG_ACTION and r2.recommendation == Recommendation.ALTERNATIVE_ACTION


def test_partial_verification(database, cloud, tools, audit_entries, incident_id) -> None:
    rules = rules_with(remove_admin_privileges={"resource_type": "IAMUser", "description": "x",
                                                "required_state": {"admin": False, "access_key_active": False}})
    remediate(database, cloud, tools, audit_entries, incident_id)
    assert verify(make_verifier(database, tools, audit_entries, rules), incident_id).verification.status == VerificationStatus.PARTIAL
    [r] = learn(make_engine(database, tools, audit_entries, vrules=rules), incident_id).learning
    assert r.feedback_type == FeedbackType.PARTIAL_RESPONSE and r.failure_reason == FailureReason.EXPECTED_STATE_NOT_REACHED
    assert r.recommendation == Recommendation.ALTERNATIVE_ACTION and r.successful is False


def test_unknown_verification_is_insufficient_evidence(database, cloud, tools, audit_entries, incident_id, monkeypatch) -> None:
    remediate(database, cloud, tools, audit_entries, incident_id)
    monkeypatch.setattr(cloud, "get_user", lambda name: (_ for _ in ()).throw(ResourceNotFoundError("gone")))
    assert verify(make_verifier(database, tools, audit_entries), incident_id).verification.status == VerificationStatus.UNKNOWN
    [r] = learn(make_engine(database, tools, audit_entries), incident_id).learning
    assert r.feedback_type == FeedbackType.INSUFFICIENT_EVIDENCE and r.failure_reason == FailureReason.INSUFFICIENT_EVIDENCE
    assert r.recommendation == Recommendation.REQUEST_HUMAN_REVIEW


def test_without_a_verification_nothing_is_learned(database, cloud, tools, audit_entries, incident_id) -> None:
    report = learn(make_engine(database, tools, audit_entries), incident_id)
    assert report.status == AgentRunStatus.SKIPPED and report.outcome == "verification_required" and report.learning == []
    with database.session() as session:
        assert LearningService(session).list() == []


def test_running_twice_does_not_duplicate(database, cloud, tools, audit_entries, incident_id) -> None:
    verified_incident(database, cloud, tools, audit_entries, incident_id)
    engine = make_engine(database, tools, audit_entries)
    first, second = learn(engine, incident_id), learn(engine, incident_id)
    assert second.outcome == "learning_exists" and first.learning[0].learning_id == second.learning[0].learning_id
    with database.session() as session:
        assert len(LearningService(session).list()) == 1


# ======================================================================== human feedback
def test_human_feedback_overrides_the_inferred_type(database, cloud, tools, audit_entries, incident_id) -> None:
    failed_incident(database, cloud, tools, audit_entries, incident_id)
    engine = make_engine(database, tools, audit_entries)
    [r] = learn(engine, incident_id).learning
    assert r.feedback_type == FeedbackType.FAILED_RESPONSE
    updated = engine.submit_human_feedback(HumanFeedbackRequest(incident_id=incident_id, feedback=HumanFeedback.CORRECT,
                                                                comment="the analyst re-checked: the response was fine"))
    assert updated.learning_id == r.learning_id and updated.human_feedback == HumanFeedback.CORRECT
    assert updated.feedback_type == FeedbackType.SUCCESSFUL_RESPONSE and updated.successful is True
    assert updated.auto_feedback_type == FeedbackType.FAILED_RESPONSE and updated.human_corrected is True
    assert updated.human_comment == "the analyst re-checked: the response was fine"
    entry = next(e for e in audit_entries if e.action == "learning.feedback_submitted")
    assert entry.actor == HumanActor.ANALYST and entry.details["effective"] == "successful_response"
    assert "comment" not in json.dumps(entry.details) or entry.details["has_comment"] is True
    for verdict, effective in ((HumanFeedback.INCORRECT, FeedbackType.FAILED_RESPONSE), (HumanFeedback.PARTIALLY_CORRECT, FeedbackType.PARTIAL_RESPONSE),
                               (HumanFeedback.NEEDS_REVIEW, FeedbackType.INSUFFICIENT_EVIDENCE)):
        assert engine.submit_human_feedback(HumanFeedbackRequest(learning_id=r.learning_id, feedback=verdict)).feedback_type == effective


def test_human_feedback_needs_exactly_one_target_and_a_record(database, cloud, tools, audit_entries, incident_id) -> None:
    engine = make_engine(database, tools, audit_entries)
    with pytest.raises(FeedbackRequestError):
        engine.submit_human_feedback(HumanFeedbackRequest(feedback=HumanFeedback.CORRECT))
    with pytest.raises(FeedbackRequestError):
        engine.submit_human_feedback(HumanFeedbackRequest(learning_id="LRN-1", incident_id=incident_id, feedback=HumanFeedback.CORRECT))
    with pytest.raises(LearningNotFoundError):
        engine.submit_human_feedback(HumanFeedbackRequest(learning_id="LRN-NOPE", feedback=HumanFeedback.CORRECT))


def test_learning_record_model_keeps_human_and_inferred_consistent() -> None:
    base = dict(incident_id="INC-1", incident_category="iam", attack_type="x", initial_severity="high", final_severity="high",
                auto_feedback_type=FeedbackType.FAILED_RESPONSE, recommendation=Recommendation.NO_FURTHER_ACTION, successful=False)
    with pytest.raises(ValueError):
        LearningRecord(**base, feedback_type=FeedbackType.SUCCESSFUL_RESPONSE)                 # no human verdict behind it
    with pytest.raises(ValueError):
        LearningRecord(**base, feedback_type=FeedbackType.SUCCESSFUL_RESPONSE, human_feedback=HumanFeedback.INCORRECT)
    with pytest.raises(ValueError):
        LearningRecord(**base, feedback_type=FeedbackType.FAILED_RESPONSE, secret="x")


# ============================================================================ controlled retry
def test_retry_request_records_count_limit_and_previous_run(database, cloud, tools, audit_entries, incident_id) -> None:
    failed_incident(database, cloud, tools, audit_entries, incident_id)
    engine = make_engine(database, tools, audit_entries)
    learn(engine, incident_id)
    remediation_run = load(database, incident_id).remediation.run_id
    state, approvals = cloud.get_cloud_state(), None
    first = engine.request_retry(incident_id, "the state regressed")
    assert (first.retry_count, first.retry_limit, first.previous_run_id, first.retry_reason) == (1, 2, remediation_run, "the state regressed")
    assert first.feedback_type == FeedbackType.RETRY_REQUESTED and first.failure_reason == FailureReason.STATE_REGRESSION
    assert engine.request_retry(incident_id, None).retry_count == 2
    with pytest.raises(FeedbackRequestError) as info:
        engine.request_retry(incident_id, "again")
    assert info.value.code == "retry_limit_reached"
    assert cloud.get_cloud_state() == state and len(tool_calls(audit_entries)) == 1        # recording a retry executes nothing
    entries = [e for e in audit_entries if e.action == "learning.retry_requested"]
    assert len(entries) == 2 and entries[0].actor == HumanActor.ANALYST and entries[1].details["retry_count"] == 2


def tool_calls(audit_entries):
    return [e for e in audit_entries if e.action == "tool:remove_admin_privileges" and e.decision == "succeeded"]


def test_retry_is_not_applicable_for_verified_or_unverified_incidents(database, cloud, tools, audit_entries, incident_id) -> None:
    engine = make_engine(database, tools, audit_entries)
    with pytest.raises(FeedbackRequestError) as info:
        engine.request_retry(incident_id, None)                                   # nothing was ever verified
    assert info.value.code == "retry_not_applicable"
    verified_incident(database, cloud, tools, audit_entries, incident_id)
    with pytest.raises(FeedbackRequestError) as info:
        engine.request_retry(incident_id, None)
    assert info.value.code == "retry_not_applicable"
    with pytest.raises(LearningNotFoundError):
        engine.request_retry("INC-NOPE", None)


def test_recommendation_changes_when_retries_are_exhausted(database, cloud, tools, audit_entries, incident_id) -> None:
    failed_incident(database, cloud, tools, audit_entries, incident_id)
    engine = make_engine(database, tools, audit_entries)
    engine.request_retry(incident_id, None)
    engine.request_retry(incident_id, None)
    [r] = learn(engine, incident_id).learning                                      # analysed AFTER both retries were used
    assert r.recommendation == Recommendation.REQUEST_HUMAN_REVIEW


# ==================================================================== regression detection
def test_regression_is_detected_recorded_and_not_remediated(database, cloud, tools, audit_entries, incident_id) -> None:
    verified_incident(database, cloud, tools, audit_entries, incident_id)
    engine = make_engine(database, tools, audit_entries)
    assert learn(engine, incident_id).regression_detected is False
    cloud.make_user_admin("alice")                                                # the resource becomes insecure again
    before = load(database, incident_id)
    report = learn(engine, incident_id)
    assert report.regression_detected is True and report.outcome.endswith("regression_detected")
    regression = next(r for r in report.learning if r.feedback_type == FeedbackType.REGRESSION_DETECTED)
    assert regression.failure_reason == FailureReason.STATE_REGRESSION and regression.successful is False
    assert regression.verification_result["expected_state"] == {"admin": False} and regression.verification_result["actual_state"] == {"admin": True}
    assert regression.recommendation == Recommendation.RETRY_SAME_ACTION
    assert "learning.regression_detected" in [e.action for e in audit_entries]
    assert cloud.get_user("alice").admin is True                                   # NOT remediated automatically
    assert len(tool_calls(audit_entries)) == 1
    after = load(database, incident_id)
    assert after.final_status == before.final_status == IncidentStatus.VERIFIED and after.verification == before.verification
    with database.session() as session:
        assert session.query(ApprovalRecord).count() == 1                          # no new approval either
    again = learn(engine, incident_id)                                              # idempotent
    with database.session() as session:
        assert len([r for r in LearningService(session).list() if r.feedback_type == FeedbackType.REGRESSION_DETECTED]) == 1
    assert again.regression_detected is True
    assert engine.request_retry(incident_id, "regressed").retry_count == 1        # a regression may be retried by a human


def test_no_regression_when_the_state_holds_or_is_unreadable(database, cloud, tools, audit_entries, incident_id, monkeypatch) -> None:
    verified_incident(database, cloud, tools, audit_entries, incident_id)
    engine = make_engine(database, tools, audit_entries)
    assert engine.check_regression(load(database, incident_id)) is None
    monkeypatch.setattr(cloud, "get_user", lambda name: (_ for _ in ()).throw(ResourceNotFoundError("gone")))
    assert engine.check_regression(load(database, incident_id)) is None            # cannot tell: no claim is made


# ======================================================================== retrieval / stats
def test_learning_retrieval_and_filters(database, cloud, tools, audit_entries, incident_id) -> None:
    failed_incident(database, cloud, tools, audit_entries, incident_id)
    learn(make_engine(database, tools, audit_entries), incident_id)
    with database.session() as session:
        service = LearningService(session)
        [r] = service.list()
        assert service.get(r.learning_id) == r and service.get("LRN-NOPE") is None
        assert service.list(incident_category="iam") == [r] and service.list(incident_category="s3") == []
        assert service.list(remediation_action="remove_admin_privileges") == [r]
        assert service.list(verification_status="failed") == [r] and service.list(verification_status="verified") == []
        assert service.list(failure_reason="state_regression") == [r] and service.list(feedback_type="failed_response") == [r]
        assert service.list(attack_type=r.attack_type) == [r] and service.list(incident_id=incident_id) == [r]


def test_statistics(database, cloud, tools, audit_entries, incident_id) -> None:
    verified_incident(database, cloud, tools, audit_entries, incident_id)
    engine = make_engine(database, tools, audit_entries)
    learn(engine, incident_id)                                                      # successful_response
    cloud.make_user_admin("alice")
    learn(engine, incident_id)                                                      # regression_detected
    verify(make_verifier(database, tools, audit_entries), incident_id)
    learn(engine, incident_id)                                                      # failed_response
    engine.submit_human_feedback(HumanFeedbackRequest(incident_id=incident_id, feedback=HumanFeedback.CORRECT))
    with database.session() as session:
        service = LearningService(session)
        s, perf = service.stats(), service.agent_performance()
    assert s["total_learning_records"] >= 3 and s["successful_responses"] >= 1 and s["failed_responses"] >= 0
    assert s["regressions"] == 1 and s["human_feedback_given"] == 1
    assert perf["verification_runs_with_a_verdict"] == 2 and perf["verification_success_rate"] == 0.5
    v = perf["agents"]["Verification Agent"]
    assert v["total_runs"] == 2 and v["successful_runs"] == 2 and v["failed_runs"] == 0 and v["average_execution_time_seconds"] >= 0
    assert perf["agents"]["Remediation Agent"]["total_runs"] >= 2                   # from the existing agent_runs table
    assert set(perf["agents"]["Verification Agent"]) >= {"total_runs", "successful_runs", "failed_runs", "partial_runs",
                                                         "average_execution_time_seconds"}


# ================================================================================= security
def test_the_engine_cannot_use_action_tools(database, cloud, tools, audit_entries, incident_id) -> None:
    enable_actions(tools)
    approval = proposed(database, tools, audit_entries, incident_id).approval
    state = cloud.get_cloud_state()
    grant = ApprovalGrant(approval_id=approval.approval_id, incident_id=incident_id, tool_name="remove_admin_privileges",
                          status=ApprovalStatus.APPROVED, decided_by="Human Analyst")
    for actor in (HumanActor.SYSTEM, AgentName.VERIFICATION):                      # the engine's audit/read identities
        for tool, args in (("remove_admin_privileges", {"username": "alice"}), ("disable_access_key", {"username": "alice"}),
                           ("isolate_instance", {"instance_id": "ec2-001"}), ("make_bucket_private", {"bucket_name": "public-assets"})):
            result = tools.execute(ToolRequest(tool_name=tool, arguments=args, requested_by=actor, incident_id=incident_id,
                                               approval=grant.model_copy(update={"tool_name": tool})))
            assert result.error_code == "permission_denied", (actor, tool)
    assert cloud.get_cloud_state() == state


def test_feedback_code_is_read_only_by_construction() -> None:
    for path in FEEDBACK_SRC.glob("*.py"):
        code = "\n".join(l for l in path.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith(("#", '"""')))
        assert not re.search(r"^\s*(from|import)\s+app\.simulator", code, re.M), path.name
        assert not re.search(r"^\s*(from|import)\s+app\.(llm|services\.approvals)", code, re.M), path.name
        assert not re.search(r"RemediationExecutor|ApprovalService|remediation\.(execution|agent)", code), path.name
        assert not re.search(r"^\s*(from|import)\s+(httpx|requests|urllib|socket|subprocess)", code, re.M), path.name
        assert not re.search(r"\b(subprocess|os\.system|eval|exec)\b|\.cloud\.|CloudSimulator", code), path.name
        for tool in re.findall(r'tool_name\s*=\s*"([a-z_]+)"', code):
            assert tool == "get_resource", (path.name, tool)
        assert not re.search(r"\.execute\(", code) or path.name == "config.py", path.name          # never calls a ToolExecutor to act


def test_no_cloud_mutation_and_no_secrets_in_records(database, cloud, tools, audit_entries, incident_id) -> None:
    keys = [k.key_id for k in cloud.get_user("alice").access_keys]
    failed_incident(database, cloud, tools, audit_entries, incident_id)
    keys += [k.key_id for k in cloud.get_user("alice").access_keys]
    state = cloud.get_cloud_state()
    engine = make_engine(database, tools, audit_entries)
    report = learn(engine, incident_id)
    engine.submit_human_feedback(HumanFeedbackRequest(incident_id=incident_id, feedback=HumanFeedback.NEEDS_REVIEW, comment="check"))
    engine.request_retry(incident_id, "why not")
    assert cloud.get_cloud_state() == state and tools.registry.agent_actions_enabled is True
    with database.session() as session:
        blob = json.dumps([r.model_dump(mode="json") for r in LearningService(session).list()], default=str)
    blob += json.dumps([e.model_dump(mode="json") for e in audit_entries if e.action.startswith("learning.")], default=str)
    assert keys and not any(k in blob for k in keys) and not re.search(r"AKIA[A-Z0-9]{6,}", blob)
    for forbidden in ("rules_your_answer_must_follow", "You are the", "chain of thought", "prompt", "password"):
        assert forbidden not in blob, forbidden
    assert report.learning[0].providers                                              # provider/model names only


def test_rules_file_is_validated(tmp_path) -> None:
    good = (CONFIG_DIR / "feedback_rules.yaml").read_text(encoding="utf-8")
    (tmp_path / "feedback_rules.yaml").write_text(good.replace("retry_limit: 2", "retry_limit: 99"), encoding="utf-8")
    with pytest.raises(FeedbackConfigError):
        load_feedback_rules(tmp_path)
    (tmp_path / "feedback_rules.yaml").write_text(good.replace("  unknown:                    {with_retries_left: request_human_review, when_exhausted: request_human_review}\n", ""), encoding="utf-8")
    with pytest.raises(FeedbackConfigError, match="recommendations missing"):
        load_feedback_rules(tmp_path)
    with pytest.raises(FeedbackConfigError, match="not found"):
        load_feedback_rules(tmp_path / "missing")
    assert isinstance(FRULES, FeedbackRules) and FRULES.retry_limit == 2


# ===================================================================================== API
@pytest.fixture()
def api(cloud: CloudSimulator, database):
    def build(provider, actions: bool = True) -> TestClient:
        app = create_app(cloud=cloud, database=database, settings=Settings(), llm_provider=provider)
        app.state.tools.agent_actions_enabled = actions
        return TestClient(app)
    return build


def executed_via_api(client: TestClient) -> str:
    incident_id = compliant_via_api(client)
    approval_id = client.post("/api/agents/remediation/run", json={"incident_id": incident_id}).json()["approval"]["approval_id"]
    assert client.post(f"/api/approvals/{approval_id}/approve").json()["outcome"] == "executed"
    assert client.post("/api/agents/verification/run", json={"incident_id": incident_id}).json()["outcome"] == "verified"
    return incident_id


def test_api_feedback_flow_with_failure_retry_and_human_feedback(api, cloud) -> None:
    with api(scripted()) as client:
        incident_id = executed_via_api(client)
        body = client.post("/api/agents/feedback/run", json={"incident_id": incident_id}).json()
        assert body["status"] == "success" and body["outcome"] == "learning_created" and body["regression_detected"] is False
        assert body["learning"][0]["feedback_type"] == "successful_response"
        cloud.make_user_admin("alice")                                             # regression
        regressed = client.post("/api/agents/feedback/run", json={"incident_id": incident_id}).json()
        assert regressed["regression_detected"] is True
        assert client.post("/api/agents/verification/run", json={"incident_id": incident_id}).json()["verification_status"] == "failed"
        client.post("/api/agents/feedback/run", json={"incident_id": incident_id})
        records = client.get("/api/learning", params={"incident_id": incident_id}).json()
        assert {r["feedback_type"] for r in records} >= {"successful_response", "regression_detected", "failed_response"}
        assert len(client.get("/api/learning", params={"failure_reason": "state_regression"}).json()) >= 1
        one = client.get(f"/api/learning/{records[0]['learning_id']}").json()
        assert one["learning_id"] == records[0]["learning_id"]
        assert client.get("/api/learning/LRN-NOPE").status_code == 404
        # human feedback overrides
        failed = next(r for r in records if r["feedback_type"] == "failed_response")
        fb = client.post("/api/learning/feedback", json={"learning_id": failed["learning_id"], "feedback": "correct", "comment": "ok"}).json()
        assert fb["feedback_type"] == "successful_response" and fb["auto_feedback_type"] == "failed_response"
        # controlled retry: a proposal + pending approval, nothing executed
        pending_before = client.get("/api/approvals", params={"status": "pending"}).json()
        retry = client.post(f"/api/incidents/{incident_id}/retry", json={"reason": "regressed again"})
        assert retry.status_code == 200, retry.text
        rb = retry.json()
        assert rb["retry"]["retry_count"] == 1 and rb["retry"]["retry_limit"] == 2 and rb["retry"]["retry_run_id"]
        assert rb["remediation"]["status"] == "success" and rb["remediation"]["approval_id"]
        assert cloud.get_user("alice").admin is True                                # NOT executed by the retry
        pending_after = client.get("/api/approvals", params={"status": "pending"}).json()
        assert len(pending_after) == len(pending_before) + 1 and pending_after[0]["status"] == "pending"
        assert client.get(f"/api/incidents/{incident_id}").json()["final_status"] == "remediation_pending"
        stats = client.get("/api/learning/stats").json()
        assert stats["service"]["kind"] == "Deterministic Backend Service" and stats["service"]["llm"] is False
        assert stats["learning"]["regressions"] == 1 and stats["learning"]["human_corrections"] == 1 and stats["learning"]["retry_requests"] == 1
        assert stats["performance"]["agents"]["Verification Agent"]["total_runs"] >= 2
        audit = {e["action"] for e in client.get("/api/audit").json()}
        assert {"learning.created", "learning.failure_analyzed", "learning.feedback_submitted", "learning.retry_requested",
                "learning.regression_detected"} <= audit
        # approval bypass is impossible: approving is still a separate human step
        assert client.post(f"/api/approvals/{rb['remediation']['approval_id']}/approve").json()["outcome"] == "executed"


def test_api_retry_limit_and_not_applicable(api, cloud) -> None:
    with api(scripted()) as client:
        incident_id = executed_via_api(client)
        assert client.post(f"/api/incidents/{incident_id}/retry").status_code == 409          # verified: not needed
        cloud.make_user_admin("alice")
        client.post("/api/agents/verification/run", json={"incident_id": incident_id})
        for expected in (200, 200):
            assert client.post(f"/api/incidents/{incident_id}/retry", json={"reason": "again"}).status_code == expected
            cloud.make_user_admin("alice")
        blocked = client.post(f"/api/incidents/{incident_id}/retry")
        assert blocked.status_code == 409 and blocked.json()["detail"]["code"] == "retry_limit_reached"
        assert client.post("/api/incidents/INC-NOPE/retry").status_code == 404


def test_api_validation(api) -> None:
    with api(scripted()) as client:
        assert client.post("/api/agents/feedback/run", json={"incident_id": "INC-NOPE"}).status_code == 404
        for path, body in (("/api/agents/feedback/run", {"incident_id": "INC-1", "action": "x"}),
                           ("/api/agents/feedback/run", {}),
                           ("/api/learning/feedback", {"incident_id": "INC-1", "feedback": "great"}),
                           ("/api/learning/feedback", {"incident_id": "INC-1", "feedback": "correct", "execute": True}),
                           ("/api/incidents/INC-1/retry", {"action": "isolate_instance"})):
            assert client.post(path, json=body).status_code == 422, (path, body)
        assert client.post("/api/learning/feedback", json={"feedback": "correct"}).status_code == 422
        assert client.post("/api/learning/feedback", json={"learning_id": "LRN-NOPE", "feedback": "correct"}).status_code == 404


def test_api_service_is_503_without_its_rules(cloud, database, tmp_path) -> None:
    with TestClient(create_app(cloud=cloud, database=database, settings=Settings(config_dir=tmp_path), llm_provider=None)) as client:
        assert client.post("/api/agents/feedback/run", json={"incident_id": "INC-1"}).status_code in (404, 503)
        assert client.post("/api/learning/feedback", json={"learning_id": "LRN-1", "feedback": "correct"}).status_code == 503
