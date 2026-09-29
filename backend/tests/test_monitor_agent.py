"""Monitor Agent end-to-end: agent runs against a real (in-memory or file) SQLite
database, the incident/audit/ledger services, the tool layer and the HTTP API."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.agents.monitor.agent import MonitorAgent
from app.agents.monitor.models import MonitorRunRequest
from app.config import Settings
from app.database.connection import Database
from app.domain.enums import AgentName, AgentRunStatus, HumanActor, IncidentStatus
from app.domain.incident import AuditEntry
from app.main import create_app
from app.services.audit_service import AuditService
from app.services.event_service import EventService
from app.services.incident_service import IncidentService
from app.simulator.attacks import AttackSimulator
from app.simulator.cloud import CloudSimulator
from app.tools.base import ToolContext, ToolKind, ToolRequest
from app.tools.executor import ToolExecutor
from app.tools.registry import ACTION_TOOL_NAMES, build_default_registry
from tests.monitor_fixtures import ALICE_IP, cloudtrail, config, event


@pytest.fixture()
def audit_entries() -> list[AuditEntry]:
    return []


@pytest.fixture()
def agent(database: Database, cloud: CloudSimulator, audit_entries: list) -> MonitorAgent:
    tools = ToolExecutor(ToolContext(cloud=cloud, database=database,
                                     registry=build_default_registry(),
                                     config_dir=Settings().config_dir),
                         audit_sink=audit_entries.append)
    return MonitorAgent(database, config(), tools, audit_sink=audit_entries.append)


def store(database: Database, events) -> list[str]:
    with database.session() as session:
        EventService(session).save_events(list(events))
    return [e.event_id for e in events]


def run_scenario(database: Database, attacks: AttackSimulator, name: str) -> list[str]:
    return store(database, attacks.run(name).events)


def incidents(database: Database):
    with database.session() as session:
        return IncidentService(session).list_incidents()


# ================================================================ incident creation
def test_suspicious_scenario_creates_one_incident(agent, database, attacks) -> None:
    ids = run_scenario(database, attacks, "iam_privilege_escalation")
    report = agent.run(MonitorRunRequest(event_ids=ids))
    assert report.processed_events == 4 and len(report.correlated_groups) == 1
    assert len(report.incidents_created) == 1 and report.incidents_updated == []
    incident = incidents(database)[0]
    assert incident.incident_id == report.incidents_created[0]
    assert incident.category.value == "iam" and incident.severity.value == "high"
    assert incident.priority.value == "P2" and incident.principal_id == "alice"
    assert incident.event_type == "AttachAdminPolicy"  # the most significant event
    assert sorted(incident.related_event_ids) == sorted(ids)
    assert incident.current_agent == AgentName.MONITOR
    assert incident.final_status == IncidentStatus.NEW
    assert incident.raw_event["eventName"] == "AttachAdminPolicy"
    assert incident.normalized_event["simulated"] is True and incident.normalized_event["fingerprint"]
    assert {(r.resource_type, r.resource_id) for r in incident.affected_resources} == {
        ("IAMUser", "alice"), ("Secret", "prod/db-password")}


def test_later_stages_are_left_pending(agent, database, attacks) -> None:
    agent.run(MonitorRunRequest(event_ids=run_scenario(database, attacks, "public_s3_exposure")))
    incident = incidents(database)[0]
    assert incident.investigation is None and incident.mitre_techniques == []
    assert incident.compliance_findings == [] and incident.remediation_plan is None
    assert incident.verification_result is None and incident.approval_required is False
    assert [d.actor for d in incident.agent_decisions] == [AgentName.MONITOR]


def test_benign_events_create_no_incident(agent, database) -> None:
    ids = store(database, [event("Login", ip=ALICE_IP, at=0),
                           event("ListUsers", ip=ALICE_IP, at=30),
                           event("DescribeInstances", ip=ALICE_IP, at=60)])
    report = agent.run(MonitorRunRequest(event_ids=ids))
    assert report.processed_events == 3 and report.incidents_created == []
    assert {g.decision for g in report.correlated_groups} == {"no_incident"}
    assert report.agent_result.outcome == "no_incident" and report.agent_result.confidence == 0.0
    assert incidents(database) == []


def test_correlated_weak_signals_create_one_incident(agent, database, attacks) -> None:
    report = agent.run(MonitorRunRequest(
        event_ids=run_scenario(database, attacks, "credential_misuse")))
    assert len(report.correlated_groups) == 1 and len(report.incidents_created) == 1
    assert report.correlated_groups[0].rules_matched == ["correlated_suspicious_group"]
    assert incidents(database)[0].category.value == "credential"


def test_separate_activities_create_separate_incidents(agent, database, attacks) -> None:
    ids = run_scenario(database, attacks, "iam_privilege_escalation")
    ids += run_scenario(database, attacks, "ec2_compromise")  # different principal (bob)
    report = agent.run(MonitorRunRequest(event_ids=ids))
    assert len(report.correlated_groups) == 2 and len(report.incidents_created) == 2
    assert report.agent_result.incident_id is None  # more than one incident touched
    assert report.agent_result.outcome == "incident_created"


def test_repeated_activity_updates_the_open_incident(agent, database, attacks) -> None:
    first = agent.run(MonitorRunRequest(event_ids=run_scenario(database, attacks, "public_s3_exposure")))
    second = agent.run(MonitorRunRequest(event_ids=run_scenario(database, attacks, "public_s3_exposure")))
    assert second.incidents_created == [] and second.incidents_updated == first.incidents_created
    assert second.agent_result.outcome == "incident_updated"
    stored = incidents(database)
    assert len(stored) == 1 and len(stored[0].related_event_ids) == 8
    assert [d.decision for d in stored[0].agent_decisions] == ["create_incident", "update_incident"]
    assert [e.action for e in stored[0].audit_log] == ["monitor.create_incident",
                                                       "monitor.update_incident"]


def test_different_category_same_principal_is_not_merged(agent, database, attacks) -> None:
    agent.run(MonitorRunRequest(event_ids=run_scenario(database, attacks, "iam_privilege_escalation")))
    report = agent.run(MonitorRunRequest(event_ids=run_scenario(database, attacks, "credential_misuse")))
    assert len(report.incidents_created) == 1 and len(incidents(database)) == 2


def test_closed_incident_is_not_reopened(agent, database, attacks) -> None:
    first = agent.run(MonitorRunRequest(event_ids=run_scenario(database, attacks, "ec2_compromise")))
    with database.session() as session:
        service = IncidentService(session)
        incident = service.get(first.incidents_created[0])
        service.save(incident.model_copy(update={"final_status": IncidentStatus.RESOLVED}))
    second = agent.run(MonitorRunRequest(event_ids=run_scenario(database, attacks, "ec2_compromise")))
    assert len(second.incidents_created) == 1 and second.incidents_updated == []


# =================================================================== dedup + reruns
def test_rerun_is_idempotent(agent, database, attacks) -> None:
    ids = run_scenario(database, attacks, "iam_privilege_escalation")
    agent.run(MonitorRunRequest(event_ids=ids))
    again = agent.run(MonitorRunRequest(event_ids=ids))
    assert sorted(again.already_processed) == sorted(ids) and again.processed_events == 0
    assert again.agent_result.outcome == "no_new_events" and len(incidents(database)) == 1
    pending = agent.run(MonitorRunRequest())  # default: only never-processed stored events
    assert pending.agent_result.status == AgentRunStatus.SKIPPED
    assert pending.agent_result.outcome == "no_events"


def test_redelivered_copy_is_a_duplicate(agent, database) -> None:
    original = event("CreateAccessKey")
    copy = original.model_copy(update={"event_id": "redelivered-1",
                                       "raw_event": {**original.raw_event, "eventID": "redelivered-1"}})
    store(database, [original, copy])
    report = agent.run(MonitorRunRequest(event_ids=[original.event_id, copy.event_id]))
    assert [d.event_id for d in report.duplicates] == ["redelivered-1"]
    assert report.processed_events == 1
    later = agent.run(MonitorRunRequest(events=[copy.model_dump(mode="json") | {"event_id": "third"}]))
    assert later.duplicates[0].kind == "previously_processed"


def test_submitted_events_are_stored_and_processed(agent, database) -> None:
    raw = [cloudtrail("AttachUserPolicy", "iam.amazonaws.com", {"userName": "alice"},
                      event_id="ct-sub-1", at=0),
           cloudtrail("CreateAccessKey", "iam.amazonaws.com", {"userName": "alice"},
                      event_id="ct-sub-2", at=30)]
    report = agent.run(MonitorRunRequest(events=raw))
    assert report.accepted_event_ids == ["ct-sub-1", "ct-sub-2"]
    assert len(report.incidents_created) == 1
    with database.session() as session:
        stored = EventService(session).get_event("ct-sub-1")
    assert stored is not None and stored.details["ingest"]["format"] == "cloudtrail"


# ===================================================================== AgentResult
def test_agent_result_contract(agent, database, attacks) -> None:
    report = agent.run(MonitorRunRequest(
        event_ids=run_scenario(database, attacks, "iam_privilege_escalation")))
    result = report.agent_result
    incident_id = report.incidents_created[0]
    assert result.agent_name == AgentName.MONITOR and result.agent_name.value == "Monitor Agent"
    assert result.status == AgentRunStatus.SUCCESS and result.outcome == "incident_created"
    assert result.incident_id == incident_id
    assert 0.8 < result.confidence <= 0.99
    assert {e.event_id for e in result.evidence} == set(report.accepted_event_ids)
    assert [(a.action, a.target) for a in result.actions] == [("create_incident", incident_id)]
    assert result.recommendations == [f"forward_to_triage:{incident_id}"]
    assert result.proposed_actions == [] and result.errors == []
    assert any(f.startswith("group:") for f in result.findings)
    per_incident = report.incident_results[0]
    assert per_incident.incident_id == incident_id
    assert "rule:suspicious_event_type" in per_incident.findings
    assert {e.kind for e in per_incident.evidence} == {"event", "cloud_state"}
    assert result.model_dump(mode="json")  # machine-readable


def test_partial_run_reports_rejections(agent, database, attacks) -> None:
    good = event("AttachAdminPolicy").model_dump(mode="json")
    report = agent.run(MonitorRunRequest(events=[good, {"junk": True}, {**good, "source": "Splunk"}]))
    assert report.agent_result.status == AgentRunStatus.PARTIAL
    assert [(r.index, r.reason) for r in report.rejected_events] == [
        (1, "unrecognized_format"), (2, "unsupported_source")]
    assert len(report.incidents_created) == 1


def test_all_rejected_run_fails_with_errors(agent) -> None:
    report = agent.run(MonitorRunRequest(events=[{"junk": True}, 42]))
    result = report.agent_result
    assert result.status == AgentRunStatus.FAILED and result.outcome == "all_events_rejected"
    assert result.errors == ["unrecognized_format:0", "schema_invalid:1"]


def test_unknown_event_ids_are_rejected_not_fatal(agent, database, attacks) -> None:
    ids = run_scenario(database, attacks, "public_s3_exposure")
    report = agent.run(MonitorRunRequest(event_ids=ids + ["no-such-event"]))
    assert report.rejected_events[0].reason == "event_not_found"
    assert report.agent_result.status == AgentRunStatus.PARTIAL and report.incidents_created


def test_internal_error_is_reported_not_raised(agent, monkeypatch) -> None:
    monkeypatch.setattr(agent, "_correlate_and_decide",
                        lambda state: (_ for _ in ()).throw(RuntimeError("boom")))
    report = agent.run(MonitorRunRequest(events=[event("Login").model_dump(mode="json")]))
    assert report.agent_result.status == AgentRunStatus.FAILED
    assert report.agent_result.errors == ["internal_error:RuntimeError"]


# ===================================================================== persistence
def test_incident_survives_database_reload(tmp_path: Path, cloud: CloudSimulator) -> None:
    url = f"sqlite:///{(tmp_path / 'agentsoc.db').as_posix()}"
    database = Database.from_url(url)
    database.ensure_schema()
    ids = run_scenario(database, AttackSimulator(cloud), "iam_privilege_escalation")
    report = MonitorAgent(database, config(), None, audit_sink=lambda e: None).run(
        MonitorRunRequest(event_ids=ids))
    database.engine.dispose()

    reopened = Database.from_url(url)
    with reopened.session() as session:
        restored = IncidentService(session).get(report.incidents_created[0])
    assert restored is not None and sorted(restored.related_event_ids) == sorted(ids)
    assert restored.evidence and restored.agent_decisions[0].decision == "create_incident"
    # the ledger survived too: a new agent on the reopened DB sees nothing new
    again = MonitorAgent(reopened, config(), None, audit_sink=lambda e: None).run(MonitorRunRequest())
    assert again.agent_result.outcome == "no_events"


def test_run_is_audited(agent, database, attacks, audit_entries) -> None:
    ids = run_scenario(database, attacks, "ec2_compromise")
    report = agent.run(MonitorRunRequest(event_ids=ids))
    by_action = {e.action: e for e in audit_entries}
    run_entry = by_action["monitor.run"]
    assert run_entry.actor == AgentName.MONITOR and run_entry.decision == "success"
    assert run_entry.incident_id == report.incidents_created[0]
    assert sorted(run_entry.details["event_ids_processed"]) == sorted(ids)
    assert run_entry.details["events_rejected"] == 0 and run_entry.details["duplicates"] == []
    assert run_entry.details["incidents_created"] == report.incidents_created
    assert run_entry.details["correlated_groups"][0]["event_ids"]
    assert by_action["monitor.create_incident"].incident_id == report.incidents_created[0]
    assert "raw_event" not in str(run_entry.details)  # no raw payloads in the audit trail


def test_rejected_events_are_audited(agent, audit_entries) -> None:
    agent.run(MonitorRunRequest(events=[{"eventName": "ConsoleLogin", "eventTime": "2026-01-01"},
                                        {"password": "hunter2"}]))
    rejections = [e for e in audit_entries if e.action == "monitor.reject_event"]
    assert [e.result for e in rejections] == ["missing_identifier", "unrecognized_format"]
    assert all("hunter2" not in str(e.model_dump()) for e in audit_entries)
    assert [e for e in audit_entries if e.action == "monitor.run"][0].decision == "failed"


# ====================================================================== security
def test_monitor_has_only_read_permissions() -> None:
    registry = build_default_registry()
    permitted = registry.permissions_for(AgentName.MONITOR)
    assert permitted and not set(permitted) & ACTION_TOOL_NAMES
    assert all(registry.get(name).kind == ToolKind.READ for name in permitted)


def test_monitor_cannot_execute_action_tools(cloud: CloudSimulator, database: Database) -> None:
    executor = ToolExecutor(ToolContext(cloud=cloud, database=database,
                                        registry=build_default_registry(agent_actions_enabled=True),
                                        config_dir=Settings().config_dir))
    for tool, args in [("disable_access_key", {"username": "alice"}),
                       ("remove_admin_privileges", {"username": "alice"}),
                       ("isolate_instance", {"instance_id": "ec2-001"}),
                       ("make_bucket_private", {"bucket_name": "public-assets"})]:
        result = executor.execute(ToolRequest(tool_name=tool, arguments=args,
                                              requested_by=AgentName.MONITOR))
        assert result.error_code == "permission_denied"
    assert cloud.get_user("alice").access_key_active and cloud.get_bucket("public-assets").public_access


def test_monitor_run_changes_no_cloud_state(agent, database, attacks, cloud) -> None:
    ids = run_scenario(database, attacks, "iam_privilege_escalation")
    before = cloud.get_cloud_state()
    agent.run(MonitorRunRequest(event_ids=ids))
    assert cloud.get_cloud_state() == before


# =========================================================================== API
def test_monitor_endpoint_after_simulation(client: TestClient) -> None:
    run = client.post("/api/simulation/run", json={"scenario": "iam_privilege_escalation"}).json()
    assert run["incident_id"] is None and run["monitor"] is None  # simulator alone: unchanged
    response = client.post("/api/agents/monitor/run", json={"event_ids": run["event_ids"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["processed_events"] == 4 and body["duplicates"] == []
    assert len(body["correlated_groups"]) == 1 and len(body["incidents_created"]) == 1
    assert body["agent_result"]["agent_name"] == "Monitor Agent"
    incident_id = body["incidents_created"][0]
    listed = client.get("/api/incidents").json()
    assert [i["incident_id"] for i in listed] == [incident_id]
    detail = client.get(f"/api/incidents/{incident_id}").json()
    assert detail["category"] == "iam" and detail["evidence"]


def test_monitor_endpoint_without_body_processes_pending_events(client: TestClient) -> None:
    client.post("/api/simulation/run", json={"scenario": "public_s3_exposure"})
    body = client.post("/api/agents/monitor/run").json()
    assert body["processed_events"] == 4 and len(body["incidents_created"]) == 1


@pytest.mark.parametrize("payload", [
    {"limit": 0},
    {"time_window_minutes": -5},
    {"event_ids": "not-a-list"},
    {"event_ids": ["a"], "events": [{}]},
    {"event_ids": [""]},
    {"unexpected": True},
])
def test_monitor_endpoint_rejects_invalid_requests(client: TestClient, payload: dict) -> None:
    assert client.post("/api/agents/monitor/run", json=payload).status_code == 422


def test_monitor_endpoint_handles_empty_event_set(client: TestClient) -> None:
    for payload in ({"event_ids": []}, {"events": []}, {}):
        body = client.post("/api/agents/monitor/run", json=payload).json()
        assert body["processed_events"] == 0 and body["incidents_created"] == []
        assert body["agent_result"]["status"] == "skipped"
        assert body["agent_result"]["outcome"] == "no_events"


def test_simulation_with_explicit_monitor_opt_in(client: TestClient) -> None:
    body = client.post("/api/simulation/run",
                       json={"scenario": "ec2_compromise", "run_monitor": True}).json()
    assert body["monitor"]["processed_events"] == 4
    assert body["incident_id"] == body["monitor"]["incidents_created"][0]
    agents = client.get("/api/agents").json()
    monitor = agents[0]
    assert monitor["stats"]["runs"] == 1 and monitor["stats"]["incidents_created"] == 1
    assert monitor["tasks_processed"] == 4 and monitor["last_activity"]
    assert monitor["last_result"]["outcome"] == "incident_created"
    assert agents[1]["stats"]["runs"] == 0  # Monitor never invokes Triage
    assert all(a["stats"] is None for a in agents[2:])
    audit = [e["action"] for e in client.get("/api/audit").json()]
    assert "monitor.run" in audit and "monitor.create_incident" in audit
    assert all(e["actor"] != "Triage Agent" for e in client.get("/api/audit").json())


def test_monitor_endpoint_returns_503_without_rules(database: Database, cloud: CloudSimulator,
                                                    tmp_path: Path) -> None:
    settings = Settings(config_dir=tmp_path)  # no monitor_rules.yaml here
    with TestClient(create_app(cloud=cloud, database=database, settings=settings)) as client:
        assert client.post("/api/agents/monitor/run").status_code == 503
        assert client.post("/api/simulation/run",
                           json={"scenario": "ec2_compromise"}).status_code == 200


def test_audit_trail_is_listed_by_api(client: TestClient, database: Database) -> None:
    client.post("/api/simulation/run", json={"scenario": "credential_misuse", "run_monitor": True})
    with database.session() as session:
        entries = AuditService(session).list_entries()
    monitor_entries = [e for e in entries if e.actor == AgentName.MONITOR]
    assert {e.action for e in monitor_entries} >= {"monitor.run", "monitor.create_incident"}
    assert all(e.actor in (AgentName.MONITOR, HumanActor.ANALYST) for e in entries)
