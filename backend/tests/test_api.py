import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from app.config import Settings
from app.database.connection import Database
from app.domain.enums import EventSource, Severity
from app.domain.incident import IncidentState
from app.main import create_app
from app.services.incident_service import IncidentService

SCENARIOS = ["iam_privilege_escalation", "public_s3_exposure", "ec2_compromise",
             "credential_misuse"]


def run(client: TestClient, scenario: str) -> dict:
    response = client.post("/api/simulation/run", json={"scenario": scenario})
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------- health
def test_healthz(client: TestClient) -> None:
    body = client.get("/api/healthz").json()
    assert body["status"] == "ok" and body["service"] == "agentsoc-backend"
    assert body["database"] == {"backend": "sqlite", "status": "ok"}
    assert body["llm_enabled"] is False and body["simulated_cloud"] is True


def test_legacy_root_and_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "healthy"}
    assert client.get("/").json()["api"] == "/api"


# ---------------------------------------------------------------------- events
def test_events_empty_then_filled_by_simulation(client: TestClient) -> None:
    assert client.get("/api/events").json() == []
    run(client, "iam_privilege_escalation")
    events = client.get("/api/events").json()
    assert len(events) == 4
    newest = events[0]
    assert newest["event_type"] == "GetSecretValue"  # newest first
    for key in ("event_id", "timestamp", "source", "account_id", "region", "event_type",
                "resource_id", "principal_id", "source_ip", "severity", "raw_event"):
        assert key in newest
    assert client.get(f"/api/events/{newest['event_id']}").json()["event_id"] == newest["event_id"]


def test_event_filters(client: TestClient) -> None:
    run(client, "iam_privilege_escalation")
    run(client, "ec2_compromise")
    assert len(client.get("/api/events", params={"user": "bob"}).json()) == 4
    assert len(client.get("/api/events", params={"event_type": "Login"}).json()) == 2
    assert len(client.get("/api/events", params={"limit": 3}).json()) == 3
    flows = client.get("/api/events", params={"source": "VPC Flow Logs"}).json()
    assert [e["event_type"] for e in flows] == ["NetworkFlowAnomaly"]
    assert client.get("/api/events", params={"limit": 0}).status_code == 422
    assert client.get("/api/events", params={"severity": "extreme"}).status_code == 422


def test_event_stats(client: TestClient) -> None:
    assert client.get("/api/events/stats").json()["total_events"] == 0
    run(client, "public_s3_exposure")
    stats = client.get("/api/events/stats").json()
    assert stats["total_events"] == 4 and stats["events_today"] == 4
    assert stats["users_with_events"] == 1
    assert stats["event_types"]["DeletePublicAccessBlock"] == 1
    assert sum(stats["by_severity"].values()) == 4
    assert stats["by_source"] == {"CloudTrail": 4}


def test_unknown_event_is_404(client: TestClient) -> None:
    assert client.get("/api/events/does-not-exist").status_code == 404


# ------------------------------------------------------------------- incidents
def test_incidents_empty_without_agents(client: TestClient) -> None:
    """Running a scenario must NOT fabricate an incident: detection is a later phase."""
    body = run(client, "iam_privilege_escalation")
    assert body["incident_id"] is None
    assert client.get("/api/incidents").json() == []
    assert client.get("/api/incidents/INC-NOPE").status_code == 404


def test_stored_incident_is_served(client: TestClient, database: Database) -> None:
    incident = IncidentState(title="Test incident", source=EventSource.CLOUDTRAIL,
                             event_type="AttachAdminPolicy", severity=Severity.HIGH)
    with database.session() as session:
        IncidentService(session).save(incident)
    listed = client.get("/api/incidents").json()
    assert [i["incident_id"] for i in listed] == [incident.incident_id]
    detail = client.get(f"/api/incidents/{incident.incident_id}").json()
    assert detail["title"] == "Test incident" and detail["severity"] == "high"
    assert client.get("/api/incidents", params={"severity": "low"}).json() == []


# ----------------------------------------------------------- agents / tools / audit
def test_only_monitor_and_triage_are_implemented(client: TestClient) -> None:
    agents = client.get("/api/agents").json()
    assert [a["name"] for a in agents] == ["Monitor Agent", "Triage Agent",
                                           "Investigator Agent", "Compliance Agent",
                                           "Remediation Agent"]
    assert [a["agent_id"] for a in agents] == ["monitor", "triage", "investigator",
                                               "compliance", "remediation"]
    monitor, triage, others = agents[0], agents[1], agents[2:]
    assert monitor["implemented"] is True and monitor["status"] == "idle"
    assert monitor["stats"]["runs"] == 0 and monitor["last_result"] is None
    assert triage["implemented"] is True and triage["stats"]["runs"] == 0
    assert triage["llm"]["configured"] is False  # tests run with LLM_PROVIDER=none
    assert all(a["implemented"] is False and a["status"] == "not_implemented"
               and a["tasks_processed"] == 0 and a["stats"] is None
               and a["last_result"] is None for a in others)
    remediation = agents[-1]
    assert "isolate_instance" in remediation["tools"]
    assert "isolate_instance" not in agents[0]["tools"]


def test_tools_endpoint(client: TestClient) -> None:
    body = client.get("/api/tools").json()
    assert body["agent_actions_enabled"] is False
    kinds = {t["name"]: t["kind"] for t in body["tools"]}
    assert kinds["make_bucket_private"] == "action" and kinds["get_incident"] == "read"


def test_approvals_are_empty(client: TestClient) -> None:
    assert client.get("/api/approvals").json() == []


def test_simulation_is_audited(client: TestClient) -> None:
    run(client, "credential_misuse")
    client.post("/api/simulation/reset")
    actions = [e["action"] for e in client.get("/api/audit").json()]
    assert actions == ["simulation.reset", "simulation.run"]


# ----------------------------------------------------------------------- cloud
def test_cloud_state(client: TestClient) -> None:
    body = client.get("/api/cloud/state").json()
    assert body["simulated"] is True
    assert body["state"]["iam_users"]["alice"]["admin"] is False
    assert body["state"]["s3_buckets"]["company-data"]["public_access"] is False
    by_name = {r["name"]: r for r in body["resources"]}
    assert by_name["company-data"]["status"] == "Healthy"
    assert by_name["public-assets"]["status"] == "Exposed"
    assert body["summary"]["total"] == len(body["resources"]) == 6


def test_cloud_state_reflects_attack(client: TestClient) -> None:
    run(client, "ec2_compromise")
    by_name = {r["name"]: r for r in client.get("/api/cloud/state").json()["resources"]}
    assert by_name["ec2-001"]["status"] == "At risk"
    assert "ec2-admin-role" in by_name["ec2-001"]["reasons"][0]


def test_cloud_action_runs_through_tool_executor(client: TestClient) -> None:
    response = client.post("/api/cloud/actions", json={
        "action": "isolate_instance", "arguments": {"instance_id": "ec2-001"}})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["outcome"] == "succeeded" and body["requested_by"] == "Human Analyst"
    assert body["output"]["new_state"] == {"status": "isolated"}
    state = client.get("/api/cloud/state").json()
    assert state["state"]["ec2_instances"]["ec2-001"]["status"] == "isolated"
    audit = client.get("/api/audit").json()[0]
    assert audit["action"] == "tool:isolate_instance" and audit["decision"] == "succeeded"


def test_cloud_action_errors(client: TestClient) -> None:
    def post(body: dict) -> int:
        return client.post("/api/cloud/actions", json=body).status_code

    assert post({"action": "isolate_instance", "arguments": {"instance_id": "ec2-999"}}) == 404
    assert post({"action": "isolate_instance", "arguments": {"instance_id": "x; rm -rf /"}}) == 422
    assert post({"action": "isolate_instance", "arguments": {"username": "alice"}}) == 422
    assert post({"action": "make_user_admin", "arguments": {"username": "alice"}}) == 422
    assert post({"action": "delete_everything", "arguments": {}}) == 422


# ------------------------------------------------------------------ simulation
def test_scenarios_listed(client: TestClient) -> None:
    names = [s["name"] for s in client.get("/api/simulation/scenarios").json()["scenarios"]]
    assert names == SCENARIOS


def test_run_simulation_end_to_end(client: TestClient) -> None:
    body = run(client, "iam_privilege_escalation")
    assert body["success"] and body["events_generated"] == 4 and body["cloud_state_changed"]
    assert {"resource_type": "IAMUser", "resource_id": "alice"} in body["affected_resources"]
    state = client.get("/api/cloud/state").json()["state"]
    assert state["iam_users"]["alice"]["admin"] is True


def test_every_scenario_runs(client: TestClient) -> None:
    for scenario in SCENARIOS:
        assert run(client, scenario)["events_generated"] == 4
    assert client.get("/api/events/stats").json()["total_events"] == 16


def test_reset_restores_cloud_and_keeps_history(client: TestClient) -> None:
    run(client, "public_s3_exposure")
    assert client.post("/api/simulation/reset").status_code == 200
    assert client.post("/api/cloud/reset").status_code == 200
    state = client.get("/api/cloud/state").json()["state"]
    assert state["s3_buckets"]["company-data"]["public_access"] is False
    assert client.get("/api/events/stats").json()["total_events"] == 4


def test_simulation_errors(client: TestClient) -> None:
    assert client.post("/api/simulation/run", json={"scenario": "nope"}).status_code == 400
    assert client.post("/api/simulation/run", json={}).status_code == 422


def test_database_unavailable_returns_503(tmp_path) -> None:
    # A SQLite file inside a directory that does not exist cannot be opened.
    engine = create_engine(f"sqlite:///{(tmp_path / 'missing' / 'x.db').as_posix()}")
    with TestClient(create_app(database=Database(engine), settings=Settings())) as client:
        health = client.get("/api/healthz")
        assert health.status_code == 200  # app still up
        assert health.json()["database"]["status"] == "unavailable"
        assert client.get("/api/events").status_code == 503
        assert client.get("/api/incidents").status_code == 503
        assert client.post("/api/simulation/run",
                           json={"scenario": "iam_privilege_escalation"}).status_code == 503
        # cloud must not stay modified when events could not be saved
        alice = client.get("/api/cloud/state").json()["state"]["iam_users"]["alice"]
        assert alice["admin"] is False


def test_postgres_unavailable_does_not_leak_credentials() -> None:
    pytest.importorskip("psycopg2")
    engine = create_engine("postgresql://user:SECRETPW@127.0.0.1:1/none",
                           connect_args={"connect_timeout": 1})
    app = create_app(database=Database(engine), settings=Settings())
    with TestClient(app) as client:
        health = client.get("/api/healthz")
        assert health.status_code == 200  # app still up
        assert health.json()["database"]["status"] == "unavailable"
        response = client.get("/api/events")
        assert response.status_code == 503
        assert "SECRETPW" not in response.text
        assert client.post("/api/simulation/run",
                           json={"scenario": "credential_misuse"}).status_code == 503
        # cloud must not stay modified when events could not be saved
        alice = client.get("/api/cloud/state").json()["state"]["iam_users"]["alice"]
        assert alice["access_keys"][0]["last_used_ip"] is None
