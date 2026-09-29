"""The /api HTTP contract used by the React dashboard.

Endpoints only wire services together; they hold no business logic. Functionality that
does not exist yet (agents, approvals) returns honest empty/structured responses.
"""

import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from app import __version__
from app.agents.monitor.agent import MonitorAgent
from app.agents.monitor.models import MonitorRunReport, MonitorRunRequest
from app.agents.registry import AgentDescriptor, list_agents
from app.agents.triage.agent import TriageAgent, TriageRunReport, TriageRunRequest
from app.api.deps import (
    get_attacks,
    get_audit_service,
    get_cloud,
    get_event_service,
    get_incident_service,
    get_monitor_agent,
    get_triage_agent,
    get_tool_executor,
    get_tool_registry,
    ready_database,
    record_audit,
)
from app.domain.enums import AgentName, EventSource, HumanActor, IncidentStatus, Severity
from app.domain.events import SecurityEvent
from app.domain.incident import AuditEntry, IncidentState
from app.services.agent_runs import AgentRunService
from app.services.audit_service import AuditService
from app.services.cloud_service import cloud_overview
from app.services.event_service import EventService
from app.services.incident_service import IncidentService
from app.services.monitor_ledger import MonitorLedgerService
from app.simulator.attacks import AttackSimulator
from app.simulator.cloud import CloudSimulator
from app.tools.base import ToolRequest
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")

SERVICE_NAME = "agentsoc-backend"

# HTTP status for each tool error code (anything unlisted -> 500).
TOOL_ERROR_STATUS = {
    "unknown_tool": 404, "resource_not_found": 404, "invalid_arguments": 422,
    "permission_denied": 403, "approval_required": 403, "approval_mismatch": 403,
    "agent_actions_disabled": 403, "database_unavailable": 503,
}


# ----------------------------------------------------------------------------- health
@router.get("/healthz")
def healthz(request: Request) -> dict[str, Any]:
    """Liveness plus database status. Always 200 while the process is up."""
    database = request.app.state.database
    db_status = "not_configured"
    if database is not None:
        try:
            ready_database(request)
            with database.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            db_status = "ok"
        except Exception:  # noqa: BLE001 - report the status, never fail liveness
            db_status = "unavailable"
    settings = request.app.state.settings
    return {
        "status": "ok",
        "service": SERVICE_NAME,
        "version": __version__,
        "database": {"backend": database.backend_name if database else None,
                     "status": db_status},
        "simulated_cloud": True,
        "llm_enabled": request.app.state.llm is not None,
        "llm_provider": settings.llm_provider,
    }


# ----------------------------------------------------------------------------- events
@router.get("/events")
def list_events(
    user: str | None = None,
    event_type: str | None = None,
    source: EventSource | None = None,
    severity: Severity | None = None,
    resource_id: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    service: EventService = Depends(get_event_service),
) -> list[SecurityEvent]:
    """Stored events, newest first, optionally filtered."""
    return service.list_events(user=user, event_type=event_type, limit=limit,
                               source=source.value if source else None,
                               severity=severity.value if severity else None,
                               resource_id=resource_id)


@router.get("/events/stats")
def event_stats(service: EventService = Depends(get_event_service)) -> dict[str, Any]:
    """Aggregate event statistics."""
    return service.get_stats()


@router.get("/events/{event_id}")
def get_event(event_id: str, service: EventService = Depends(get_event_service)) -> SecurityEvent:
    """One stored event."""
    event = service.get_event(event_id)
    if event is None:
        raise HTTPException(404, f"event '{event_id}' not found")
    return event


# -------------------------------------------------------------------------- incidents
@router.get("/incidents")
def list_incidents(
    status: IncidentStatus | None = None,
    severity: Severity | None = None,
    limit: int = Query(100, ge=1, le=1000),
    service: IncidentService = Depends(get_incident_service),
) -> list[IncidentState]:
    """Incidents, newest first (created by the Monitor Agent)."""
    return service.list_incidents(status=status.value if status else None,
                                  severity=severity.value if severity else None, limit=limit)


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str,
                 service: IncidentService = Depends(get_incident_service)) -> IncidentState:
    incident = service.get(incident_id)
    if incident is None:
        raise HTTPException(404, f"incident '{incident_id}' not found")
    return incident


# ----------------------------------------------------------------- agents, tools, audit
@router.get("/agents")
def agents(request: Request,
           tools: ToolRegistry = Depends(get_tool_registry)) -> list[AgentDescriptor]:
    """The five agents. Only the Monitor Agent is implemented and reports activity."""
    stats = triage_stats = None
    try:
        with ready_database(request).session() as session:
            stats = MonitorLedgerService(session).stats()
            triage_stats = AgentRunService(session).stats(AgentName.TRIAGE.value)
    except Exception:  # noqa: BLE001 - descriptors are still useful without stats
        logger.warning("agent stats unavailable")
    return list_agents(tools, monitor_stats=stats, triage_stats=triage_stats,
                       triage_llm=_llm_info(request))


def _llm_info(request: Request) -> dict[str, Any]:
    provider = request.app.state.llm
    settings = request.app.state.settings
    return {"configured": provider is not None,
            "provider": provider.name if provider else settings.llm_provider,
            "model": provider.model if provider else None,
            "error": request.app.state.llm_error}


@router.get("/llm/status")
def llm_status(request: Request) -> dict[str, Any]:
    """Configured LLM provider and whether it is reachable right now (no secrets)."""
    provider = request.app.state.llm
    info = _llm_info(request)
    if provider is None:
        return {**info, "reachable": False, "model_available": None,
                "detail": info["error"] or "LLM_PROVIDER=none"}
    status = provider.status()
    return {**info, "reachable": status.reachable, "model_available": status.model_available,
            "detail": status.detail}


@router.post("/agents/triage/run")
def run_triage(body: TriageRunRequest,
               incidents: IncidentService = Depends(get_incident_service),
               agent: TriageAgent = Depends(get_triage_agent)) -> TriageRunReport:
    """Triage ONE incident (read-only evidence + LLM + validation). Calls no other agent.
    Failed runs (e.g. LLM unavailable) return 200 with status=failed and a machine-readable
    outcome; the incident is left unchanged in that case."""
    if incidents.get(body.incident_id) is None:
        raise HTTPException(404, f"incident '{body.incident_id}' not found")
    return agent.run(body)


@router.post("/agents/monitor/run")
def run_monitor(body: MonitorRunRequest | None = None,
                agent: MonitorAgent = Depends(get_monitor_agent)) -> MonitorRunReport:
    """Run the Monitor Agent (deterministic, read-only). With no body it processes every
    stored event it has not processed yet. It calls no other agent."""
    return agent.run(body or MonitorRunRequest())


@router.get("/tools")
def tools(registry: ToolRegistry = Depends(get_tool_registry)) -> dict[str, Any]:
    """Registered tools and which actors may use each."""
    return {
        "agent_actions_enabled": registry.agent_actions_enabled,
        "tools": [{**spec.describe(),
                   "permitted_actors": sorted(a.value for a in registry.actors_permitted(spec.name))}
                  for spec in registry.list_specs()],
    }


@router.get("/audit")
def audit(incident_id: str | None = None, limit: int = Query(200, ge=1, le=1000),
          service: AuditService = Depends(get_audit_service)) -> list[AuditEntry]:
    """Audit trail, newest first."""
    return service.list_entries(incident_id=incident_id, limit=limit)


@router.get("/approvals")
def approvals() -> list[dict[str, Any]]:
    """Pending human approvals. The approval workflow arrives with the Remediation Agent."""
    return []


# ------------------------------------------------------------------------------ cloud
class CloudActionRequest(BaseModel):
    """An analyst-initiated containment action (runs through the tool executor)."""

    action: Literal["disable_access_key", "remove_admin_privileges",
                    "isolate_instance", "make_bucket_private"]
    arguments: dict[str, Any] = Field(default_factory=dict)
    incident_id: str | None = None
    reason: str = Field(default="", max_length=2000)


@router.get("/cloud/state")
def cloud_state(cloud: CloudSimulator = Depends(get_cloud)) -> dict[str, Any]:
    """Simulated cloud: raw state, flat resource inventory and posture counts."""
    return cloud_overview(cloud)


@router.post("/cloud/reset")
def reset_cloud(request: Request, cloud: CloudSimulator = Depends(get_cloud)) -> dict[str, Any]:
    """Reset ONLY the simulated cloud. Stored events are kept."""
    cloud.reset()
    record_audit(request, AuditEntry(actor=HumanActor.ANALYST, action="cloud.reset",
                                     decision="executed", result="cloud state reset"))
    return {"success": True, "message": "cloud state reset", **cloud_overview(cloud)}


@router.post("/cloud/actions")
def cloud_action(body: CloudActionRequest,
                 executor: ToolExecutor = Depends(get_tool_executor)) -> JSONResponse:
    """Run one allow-listed action as the human analyst (the analyst's call is the approval)."""
    result = executor.execute(ToolRequest(
        tool_name=body.action, arguments=body.arguments, requested_by=HumanActor.ANALYST,
        incident_id=body.incident_id, reason=body.reason))
    status = 200 if result.ok else TOOL_ERROR_STATUS.get(result.error_code or "", 500)
    return JSONResponse(status_code=status, content=result.model_dump(mode="json"))


# ------------------------------------------------------------------------- simulation
class RunRequest(BaseModel):
    scenario: str
    # Explicit opt-in: also run the Monitor Agent on the generated events. Default off, so
    # the simulator still runs on its own exactly as before.
    run_monitor: bool = False


def valid_run_request(body: RunRequest,
                      attacks: AttackSimulator = Depends(get_attacks)) -> RunRequest:
    """Reject unknown scenarios (400) before any database work happens."""
    names = [s["name"] for s in attacks.list_scenarios()]
    if body.scenario not in names:
        raise HTTPException(400, f"unknown scenario '{body.scenario}'. Valid: {', '.join(names)}")
    return body


@router.get("/simulation/scenarios")
def list_scenarios(attacks: AttackSimulator = Depends(get_attacks)) -> dict[str, Any]:
    return {"scenarios": attacks.list_scenarios()}


@router.post("/simulation/run")
def run_simulation(
    request: Request,
    body: RunRequest = Depends(valid_run_request),
    service: EventService = Depends(get_event_service),
) -> dict[str, Any]:
    """Reset the cloud, run a scenario, persist its events, return everything.

    The simulator itself creates no incident. Detection is the Monitor Agent's job: call
    POST /api/agents/monitor/run with the returned event IDs, or pass run_monitor=true.
    """
    scenario = body.scenario
    cloud, attacks = request.app.state.cloud, request.app.state.attacks
    with request.app.state.run_lock:
        cloud.reset()
        result = attacks.run(scenario)
        try:
            service.save_events(list(result.events))
        except Exception:
            cloud.reset()  # don't leave a changed cloud without stored events
            raise
    record_audit(request, AuditEntry(
        actor=HumanActor.ANALYST, action="simulation.run", decision="executed",
        result=f"{len(result.events)} events generated",
        details={"scenario": scenario, "scenario_id": result.scenario_id}))
    monitor = None
    if body.run_monitor:  # explicit opt-in; only the Monitor Agent is ever invoked here
        monitor = get_monitor_agent(request).run(
            MonitorRunRequest(event_ids=[e.event_id for e in result.events]))
    return {
        "success": True,
        "scenario": scenario,
        "scenario_id": result.scenario_id,
        "description": result.description,
        "events_generated": len(result.events),
        "events": [e.model_dump(mode="json") for e in result.events],
        "affected_resources": [r.model_dump() for r in result.affected_resources],
        "attack_start_time": result.attack_start_time,
        "attack_end_time": result.attack_end_time,
        "state_changes": [c.model_dump(mode="json") for c in result.state_changes],
        "cloud_state_changed": result.cloud_state_changed,
        "event_ids": [e.event_id for e in result.events],
        "incident_id": monitor.agent_result.incident_id if monitor else None,
        "monitor": monitor.model_dump(mode="json") if monitor else None,
    }


@router.post("/simulation/reset")
def reset_simulation(request: Request,
                     cloud: CloudSimulator = Depends(get_cloud)) -> dict[str, Any]:
    """Reset the simulated cloud. Database history is preserved."""
    cloud.reset()
    record_audit(request, AuditEntry(actor=HumanActor.ANALYST, action="simulation.reset",
                                     decision="executed", result="cloud state reset"))
    return {"success": True, "message": "simulation reset; event history preserved",
            **cloud_overview(cloud)}
