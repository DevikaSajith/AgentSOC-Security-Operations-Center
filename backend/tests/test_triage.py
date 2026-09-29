"""Triage Agent tests. The LLM is always the deterministic MockLLMProvider."""

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.agents.monitor.agent import MonitorAgent
from app.agents.monitor.models import MonitorRunRequest
from app.agents.triage.agent import TriageAgent, TriageRunRequest
from app.agents.triage.config import load_triage_config
from app.agents.triage.context import ContextBuilder, sanitize
from app.agents.triage.prompts import SYSTEM_PROMPT
from app.agents.triage.validation import TriageValidationError, validate_decision
from app.config import Settings
from app.database.connection import Database
from app.domain.enums import (
    AgentName,
    AgentRunStatus,
    IncidentCategory,
    IncidentStatus,
    Priority,
    Severity,
    TriageMethod,
    TriageNextStep,
)
from app.domain.incident import AuditEntry, IncidentState
from app.domain.triage import TriageDecision
from app.llm.mock import MockLLMProvider
from app.main import create_app
from app.services.event_service import EventService
from app.services.incident_service import IncidentService
from app.simulator.attacks import AttackSimulator
from app.simulator.cloud import CloudSimulator
from app.tools.base import ToolContext, ToolKind, ToolRequest
from app.tools.executor import ToolExecutor
from app.tools.registry import ACTION_TOOL_NAMES, build_default_registry
from tests.monitor_fixtures import config as monitor_config

TRIAGE_CONFIG = load_triage_config(Settings().config_dir)


def decision(**overrides) -> dict:
    """A valid model answer for an incident whose context has EV1..EV4 and PR1."""
    base = {
        "severity": "critical", "priority": "P1", "category": "iam", "confidence": 0.82,
        "classification": "Privilege escalation of an IAM user",
        "summary": "An untrusted IP created an access key and attached an admin policy to alice, "
                   "then read a production secret.",
        "severity_rationale": "Raised from high: admin rights plus secret access by an untrusted source.",
        "priority_rationale": "P1 because the principal now holds admin rights and credentials exist.",
        "risk_indicators": [{"indicator": "Admin policy attached from untrusted IP", "evidence_refs": ["EV3"]},
                            {"indicator": "Principal is now an administrator", "evidence_refs": ["PR1"]}],
        "key_evidence": ["EV2", "EV3", "EV4", "PR1"],
        "investigation_required": True,
        "investigation_reason": "Likely privilege escalation with credential creation.",
        "recommended_next_step": "investigate",
    }
    return {**base, **overrides}


def answer(**overrides) -> str:
    return json.dumps(decision(**overrides))


# ============================================================================ fixtures
@pytest.fixture()
def audit_entries() -> list[AuditEntry]:
    return []


@pytest.fixture()
def tools(cloud: CloudSimulator, database: Database, audit_entries) -> ToolExecutor:
    return ToolExecutor(ToolContext(cloud=cloud, database=database, registry=build_default_registry(),
                                    config_dir=Settings().config_dir), audit_sink=audit_entries.append)


@pytest.fixture()
def incident_id(database: Database, cloud: CloudSimulator, tools: ToolExecutor) -> str:
    """A real Monitor-created incident from the IAM privilege escalation scenario."""
    events = AttackSimulator(cloud).run("iam_privilege_escalation").events
    with database.session() as session:
        EventService(session).save_events(events)
    report = MonitorAgent(database, monitor_config(), tools, audit_sink=lambda e: None).run(
        MonitorRunRequest(event_ids=[e.event_id for e in events]))
    return report.incidents_created[0]


def make_agent(database, tools, audit_entries, provider) -> TriageAgent:
    return TriageAgent(database, TRIAGE_CONFIG, provider, tools, audit_sink=audit_entries.append)


def stored(database: Database, incident_id: str) -> IncidentState:
    with database.session() as session:
        return IncidentService(session).get(incident_id)


# ============================================================================ schema
def test_valid_triage_decision() -> None:
    parsed = TriageDecision.model_validate(decision(severity="HIGH", priority="p2",
                                                    recommended_next_step="INVESTIGATE"))
    assert (parsed.severity, parsed.priority, parsed.recommended_next_step) == (
        Severity.HIGH, Priority.P2, TriageNextStep.INVESTIGATE)


@pytest.mark.parametrize("field, value", [
    ("severity", "catastrophic"), ("priority", "P0"), ("priority", "urgent"),
    ("category", "database"), ("confidence", 2.7), ("confidence", -5),
    ("recommended_next_step", "remediate_now"), ("recommended_next_step", "run rm -rf /"),
    ("key_evidence", []), ("risk_indicators", []), ("summary", "short"),
])
def test_invalid_decision_values_are_rejected(field: str, value) -> None:
    with pytest.raises(ValidationError):
        TriageDecision.model_validate(decision(**{field: value}))


def test_unknown_fields_and_missing_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        TriageDecision.model_validate({**decision(), "execute": "disable_access_key"})
    incomplete = decision()
    del incomplete["investigation_required"]
    with pytest.raises(ValidationError):
        TriageDecision.model_validate(incomplete)


# ======================================================================== validation
ALLOWED = {"EV1", "EV2", "EV3", "EV4", "PR1"}


def rejected(text: str, allowed=ALLOWED) -> TriageValidationError:
    with pytest.raises(TriageValidationError) as info:
        validate_decision(text, allowed, TRIAGE_CONFIG)
    return info.value


def test_unknown_evidence_refs_are_rejected() -> None:
    err = rejected(answer(key_evidence=["EV1", "EV99"]))
    assert err.code == "semantic_invalid" and "EV99" in err.problems[0]
    assert rejected(answer(risk_indicators=[{"indicator": "made up", "evidence_refs": ["X1"]}])
                    ).code == "semantic_invalid"


def test_next_step_must_match_investigation_flag() -> None:
    assert rejected(answer(investigation_required=False)).code == "semantic_invalid"
    assert rejected(answer(recommended_next_step="monitor")).code == "semantic_invalid"


@pytest.mark.parametrize("overrides", [
    {"severity": "high", "priority": "P3", "recommended_next_step": "close",
     "investigation_required": False, "confidence": 0.95},             # close at high severity
    {"severity": "low", "priority": "P4", "recommended_next_step": "close",
     "investigation_required": False, "confidence": 0.5},              # close with low confidence
    {"severity": "medium", "priority": "P1"},                          # P1 below high severity
    {"severity": "critical", "priority": "P3"},                        # critical but low priority
])
def test_policy_violations_are_rejected(overrides: dict) -> None:
    assert rejected(answer(**overrides)).code == "policy_violation"


def test_non_json_output_is_rejected() -> None:
    assert rejected("I think this is bad.").code == "invalid_json"
    assert rejected('{"severity": "high"}').code == "schema_invalid"


# ============================================================================ agent
def test_successful_triage_updates_incident(database, tools, audit_entries, incident_id) -> None:
    before = stored(database, incident_id)
    report = make_agent(database, tools, audit_entries, MockLLMProvider([answer()])).run(
        TriageRunRequest(incident_id=incident_id))
    assert report.status == AgentRunStatus.SUCCESS and report.outcome == "triaged"
    assert report.method == TriageMethod.LLM and report.attempts == 1
    incident = stored(database, incident_id)
    assert (incident.severity, incident.priority, incident.category) == (
        Severity.CRITICAL, Priority.P1, IncidentCategory.IAM)
    assert incident.confidence == 0.82
    assert incident.final_status == IncidentStatus.TRIAGED and incident.current_agent == AgentName.TRIAGE
    triage = incident.triage
    assert triage.previous.severity == before.severity == Severity.HIGH  # Monitor's initial signal
    assert triage.provider == "mock" and triage.model == "mock-triage-1"
    assert sorted(triage.input_event_ids) == sorted(before.related_event_ids)
    assert triage.investigation_required and triage.recommended_next_step == TriageNextStep.INVESTIGATE
    # later stages untouched
    assert incident.investigation is None and incident.remediation_plan is None


def test_evidence_and_interpretation_are_separated(database, tools, audit_entries, incident_id) -> None:
    make_agent(database, tools, audit_entries, MockLLMProvider([answer()])).run(
        TriageRunRequest(incident_id=incident_id))
    triage = stored(database, incident_id).triage
    observed = {o.ref: o for o in triage.observed_evidence}
    assert set(observed) == {"EV2", "EV3", "EV4", "PR1"}
    incident_events = set(stored(database, incident_id).related_event_ids)
    for ref in ("EV2", "EV3", "EV4"):
        assert observed[ref].kind == "event" and observed[ref].event_id in incident_events
    assert "AttachAdminPolicy by alice" in observed["EV3"].fact   # system text, from the event
    assert "untrusted IP created" not in " ".join(o.fact for o in triage.observed_evidence)
    assert triage.interpretation.summary.startswith("An untrusted IP created")  # model text
    assert triage.interpretation.risk_indicators[0].evidence_refs == ["EV3"]


def test_llm_unavailable_leaves_incident_unchanged(database, tools, audit_entries, incident_id) -> None:
    before = stored(database, incident_id)
    report = make_agent(database, tools, audit_entries, MockLLMProvider(available=False)).run(
        TriageRunRequest(incident_id=incident_id))
    assert report.status == AgentRunStatus.FAILED and report.outcome == "llm_unavailable"
    assert report.triage is None and report.agent_result.errors
    after = stored(database, incident_id)
    assert after.triage is None and after.severity == before.severity
    assert after.final_status == IncidentStatus.NEW


def test_no_provider_configured(database, tools, audit_entries, incident_id) -> None:
    report = make_agent(database, tools, audit_entries, None).run(TriageRunRequest(incident_id=incident_id))
    assert report.outcome == "llm_not_configured" and report.status == AgentRunStatus.FAILED


def test_malformed_output_is_repaired_once(database, tools, audit_entries, incident_id) -> None:
    mock = MockLLMProvider(["<think>hidden</think> not json at all", answer()])
    report = make_agent(database, tools, audit_entries, mock).run(TriageRunRequest(incident_id=incident_id))
    assert report.status == AgentRunStatus.SUCCESS and report.attempts == 2
    assert report.validation_errors[0].startswith("invalid_json")
    assert "rejected by validation" in mock.calls[1]["user"]  # constrained repair request
    assert "hidden" not in json.dumps(report.model_dump(mode="json"))  # no reasoning stored


def test_persistent_invalid_output_fails_without_corruption(database, tools, audit_entries,
                                                            incident_id) -> None:
    mock = MockLLMProvider([answer(key_evidence=["EV42"])])  # always cites invented evidence
    report = make_agent(database, tools, audit_entries, mock).run(TriageRunRequest(incident_id=incident_id))
    assert report.status == AgentRunStatus.FAILED and report.outcome == "invalid_llm_output"
    assert report.attempts == 1 + TRIAGE_CONFIG.policy.max_repair_attempts == len(mock.calls)
    assert stored(database, incident_id).triage is None
    failed = [e for e in audit_entries if e.action == "triage.failed"]
    assert failed and failed[0].result == "invalid_llm_output"


def test_policy_violation_outcome(database, tools, audit_entries, incident_id) -> None:
    mock = MockLLMProvider([answer(severity="medium", priority="P1")])
    report = make_agent(database, tools, audit_entries, mock).run(TriageRunRequest(incident_id=incident_id))
    assert report.outcome == "policy_violation" and stored(database, incident_id).triage is None


def test_rule_based_fallback_only_when_requested(database, tools, audit_entries, incident_id) -> None:
    down = MockLLMProvider(available=False)
    report = make_agent(database, tools, audit_entries, down).run(
        TriageRunRequest(incident_id=incident_id, allow_rule_based_fallback=True))
    assert report.status == AgentRunStatus.SUCCESS
    assert report.outcome == "triaged_rule_based_fallback"
    assert report.method == TriageMethod.RULE_BASED_FALLBACK
    triage = stored(database, incident_id).triage
    assert triage.method == TriageMethod.RULE_BASED_FALLBACK and triage.provider == "rule_based"
    assert triage.severity == Severity.CRITICAL  # high + privileged principal -> critical
    assert "rule-based" in triage.interpretation.classification.lower()
    assert report.validation_errors[0].startswith("llm_unavailable")  # why the fallback was used


def test_triage_does_not_change_cloud_state(database, tools, audit_entries, incident_id, cloud) -> None:
    before = cloud.get_cloud_state()
    make_agent(database, tools, audit_entries, MockLLMProvider([answer()])).run(
        TriageRunRequest(incident_id=incident_id))
    assert cloud.get_cloud_state() == before


def test_agent_result_contract(database, tools, audit_entries, incident_id) -> None:
    result = make_agent(database, tools, audit_entries, MockLLMProvider([answer()])).run(
        TriageRunRequest(incident_id=incident_id)).agent_result
    assert result.agent_name == AgentName.TRIAGE and result.incident_id == incident_id
    assert result.confidence == 0.82 and result.outcome == "triaged"
    assert "severity:high->critical" in result.findings and "next_step:investigate" in result.findings
    assert all(e.event_id or e.kind != "event" for e in result.evidence) and len(result.evidence) == 4
    assert [a.action for a in result.actions] == ["update_incident"]
    assert result.proposed_actions == []  # triage proposes no tool actions


# ========================================================================= security
def test_triage_has_only_read_permissions() -> None:
    registry = build_default_registry()
    permitted = set(registry.permissions_for(AgentName.TRIAGE))
    assert permitted == {"get_incident", "get_resource", "get_iam_entity", "get_cloudtrail_events",
                         "get_security_findings", "get_network_events", "get_asset_context"}
    assert not permitted & ACTION_TOOL_NAMES
    assert all(registry.get(n).kind == ToolKind.READ for n in permitted)


def test_triage_cannot_execute_action_tools(cloud, database) -> None:
    executor = ToolExecutor(ToolContext(cloud=cloud, database=database,
                                        registry=build_default_registry(agent_actions_enabled=True),
                                        config_dir=Settings().config_dir))
    for tool, args in [("disable_access_key", {"username": "alice"}),
                       ("remove_admin_privileges", {"username": "alice"}),
                       ("isolate_instance", {"instance_id": "ec2-001"}),
                       ("make_bucket_private", {"bucket_name": "public-assets"})]:
        result = executor.execute(ToolRequest(tool_name=tool, arguments=args,
                                              requested_by=AgentName.TRIAGE))
        assert result.error_code == "permission_denied"


def test_arbitrary_tool_requests_are_rejected(cloud, database) -> None:
    executor = ToolExecutor(ToolContext(cloud=cloud, database=database, registry=build_default_registry(),
                                        config_dir=Settings().config_dir))
    assert executor.execute(ToolRequest(tool_name="run_shell", requested_by=AgentName.TRIAGE,
                                        arguments={"cmd": "whoami"})).error_code == "unknown_tool"
    with pytest.raises(ValidationError):
        ToolRequest(tool_name="http://evil/get", requested_by=AgentName.TRIAGE)
    # a model answer that tries to add an action is simply invalid output
    with pytest.raises(ValidationError):
        TriageDecision.model_validate({**decision(), "actions": [{"tool": "disable_access_key"}]})


def test_context_contains_no_credentials(database, tools, incident_id) -> None:
    context = ContextBuilder(TRIAGE_CONFIG, tools).build(stored(database, incident_id))
    text = context.to_json()
    assert not re.search(r"AKIA[A-Z0-9]{8,}", text)  # simulated access key IDs never sent
    assert "key_id" not in text
    assert not re.search(r'"[^"]*(password|secret|token|credential)[^"]*"\s*:', text, re.I)  # no such keys
    assert context.payload["principal"]["access_keys_total"] == 2
    assert context.payload["principal"]["admin"] is True
    assert "incident_confidence" not in text  # Monitor's number is not shown to the model
    assert len(text) <= TRIAGE_CONFIG.context.max_context_chars
    assert set(context.facts) == {"EV1", "EV2", "EV3", "EV4", "PR1", "RS1", "MF1"}


def test_sanitize_masks_secrets() -> None:
    cleaned = sanitize({"api_key": "x", "nested": {"SecretValue": "y", "ok": "AKIASIM1234567890 used"},
                        "items": [{"session_token": "z", "name": "n"}]})
    assert cleaned == {"nested": {"ok": "[redacted] used"}, "items": [{"name": "n"}]}


def test_audit_contains_no_secrets_prompts_or_raw_output(database, tools, audit_entries,
                                                         incident_id) -> None:
    mock = MockLLMProvider(["<think>secret chain of thought</think>{", answer()])
    make_agent(database, tools, audit_entries, mock).run(TriageRunRequest(incident_id=incident_id))
    dumped = json.dumps([e.model_dump(mode="json") for e in audit_entries])
    assert "chain of thought" not in dumped
    assert SYSTEM_PROMPT[:60] not in dumped and "Context (JSON)" not in dumped
    assert not re.search(r"AKIA[A-Z0-9]{8,}", dumped)


# ======================================================================= idempotency
def test_running_twice_is_safe(database, tools, audit_entries, incident_id) -> None:
    agent = make_agent(database, tools, audit_entries,
                       MockLLMProvider([answer(), answer(severity="high", priority="P2")]))
    first = agent.run(TriageRunRequest(incident_id=incident_id))
    second = agent.run(TriageRunRequest(incident_id=incident_id))
    incident = stored(database, incident_id)
    with database.session() as session:
        assert len(IncidentService(session).list_incidents()) == 1
    assert incident.triage.run_id == second.run_id != first.run_id  # latest valid wins
    assert incident.severity == Severity.HIGH
    assert incident.triage.previous.severity == Severity.HIGH  # still the Monitor's value
    assert [d.actor for d in incident.agent_decisions] == [AgentName.MONITOR, AgentName.TRIAGE]
    assert len(incident.triage.observed_evidence) == 4  # not accumulated across runs


def test_each_run_is_audited_separately(database, tools, audit_entries, incident_id) -> None:
    agent = make_agent(database, tools, audit_entries, MockLLMProvider([answer()]))
    ids = {agent.run(TriageRunRequest(incident_id=incident_id)).run_id for _ in range(2)}
    runs = [e for e in audit_entries if e.action == "triage.run"]
    done = [e for e in audit_entries if e.action == "triage.completed"]
    assert len(ids) == 2 and len(runs) == 2 and len(done) == 2
    assert {e.details["run_id"] for e in done} == ids
    entry = done[-1]
    assert entry.details["provider"] == "mock" and entry.details["model"] == "mock-triage-1"
    assert entry.details["decision"]["recommended_next_step"] == "investigate"
    assert sorted(entry.details["input_event_ids"]) == sorted(stored(database, incident_id).related_event_ids)


# ============================================================================== API
@pytest.fixture()
def api(cloud: CloudSimulator, database: Database):
    def build(provider) -> TestClient:
        return TestClient(create_app(cloud=cloud, database=database, settings=Settings(),
                                     llm_provider=provider))
    return build


def create_incident(client: TestClient) -> str:
    body = client.post("/api/simulation/run",
                       json={"scenario": "iam_privilege_escalation", "run_monitor": True}).json()
    return body["incident_id"]


def test_triage_endpoint_success(api) -> None:
    with api(MockLLMProvider([answer()])) as client:
        incident_id = create_incident(client)
        response = client.post("/api/agents/triage/run", json={"incident_id": incident_id})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "success" and body["outcome"] == "triaged"
        assert body["agent_result"]["agent_name"] == "Triage Agent"
        triage = client.get(f"/api/incidents/{incident_id}").json()["triage"]
        # the fields the frontend renders
        for key in ("severity", "priority", "category", "confidence", "investigation_required",
                    "recommended_next_step", "provider", "model", "timestamp", "method",
                    "observed_evidence", "interpretation", "previous"):
            assert key in triage
        assert triage["interpretation"]["classification"] == "Privilege escalation of an IAM user"
        assert client.get(f"/api/incidents/{incident_id}").json()["final_status"] == "triaged"
        agents = client.get("/api/agents").json()
        triage_agent = agents[1]
        assert triage_agent["stats"]["runs"] == 1 and triage_agent["stats"]["successful_runs"] == 1
        assert triage_agent["stats"]["last_incident_id"] == incident_id
        assert triage_agent["llm"] == {"configured": True, "provider": "mock",
                                       "model": "mock-triage-1", "error": None}
        actions = [e["action"] for e in client.get("/api/audit").json()]
        assert {"triage.run", "triage.completed"} <= set(actions)


@pytest.mark.parametrize("payload, status", [
    ({"incident_id": "INC-X", "unexpected": 1}, 422),
    ({}, 422),
    ({"incident_id": "../etc/passwd"}, 422),
    ({"incident_id": "INC-DOESNOTEXIST"}, 404),
])
def test_triage_endpoint_rejects_bad_requests(api, payload: dict, status: int) -> None:
    with api(MockLLMProvider([answer()])) as client:
        assert client.post("/api/agents/triage/run", json=payload).status_code == status


def test_triage_endpoint_llm_unavailable(api) -> None:
    with api(MockLLMProvider(available=False)) as client:
        incident_id = create_incident(client)
        body = client.post("/api/agents/triage/run", json={"incident_id": incident_id}).json()
        assert body["status"] == "failed" and body["outcome"] == "llm_unavailable"
        assert body["triage"] is None and body["agent_result"]["errors"]
        assert client.get(f"/api/incidents/{incident_id}").json()["triage"] is None
        stats = client.get("/api/agents").json()[1]["stats"]
        assert stats["failed_runs"] == 1 and stats["successful_runs"] == 0
        assert "triage.failed" in [e["action"] for e in client.get("/api/audit").json()]
        assert client.get("/api/llm/status").json()["reachable"] is False


def test_triage_endpoint_response_validates_against_models(api) -> None:
    from app.agents.triage.agent import TriageRunReport
    with api(MockLLMProvider([answer()])) as client:
        incident_id = create_incident(client)
        body = client.post("/api/agents/triage/run", json={"incident_id": incident_id}).json()
    report = TriageRunReport.model_validate(body)
    assert report.triage is not None and report.triage.severity == Severity.CRITICAL


def test_backend_stays_up_without_llm(cloud, database) -> None:
    settings = Settings(llm_provider="ollama", llm_model="m", ollama_base_url="not a url")
    with TestClient(create_app(cloud=cloud, database=database, settings=settings)) as client:
        assert client.get("/api/healthz").json()["llm_enabled"] is False
        status = client.get("/api/llm/status").json()
        assert status["configured"] is False and "OLLAMA_BASE_URL" in status["detail"]
        incident_id = create_incident(client)  # Monitor still works
        body = client.post("/api/agents/triage/run", json={"incident_id": incident_id}).json()
        assert body["outcome"] == "llm_not_configured"


def test_triage_endpoint_returns_503_without_rules(cloud, database, tmp_path: Path) -> None:
    with TestClient(create_app(cloud=cloud, database=database, settings=Settings(config_dir=tmp_path),
                               llm_provider=MockLLMProvider([answer()]))) as client:
        assert client.post("/api/agents/triage/run", json={"incident_id": "INC-1"}).status_code in (404, 503)
