"""Descriptions of the five agents and which are implemented.

Monitor and Triage are implemented. The other three report `implemented: false`, no
activity and no results. Permitted tools always come from the tool registry.
"""

from typing import Any, Literal

from pydantic import BaseModel

from app.domain.enums import AgentName
from app.tools.registry import ToolRegistry

AgentStatus = Literal["not_implemented", "idle", "running", "paused", "error"]

IMPLEMENTED = frozenset({AgentName.MONITOR, AgentName.TRIAGE})


class AgentDescriptor(BaseModel):
    agent_id: str
    name: AgentName
    purpose: str
    input: str
    output: str
    tools: list[str]
    implemented: bool = False
    status: AgentStatus = "not_implemented"
    tasks_processed: int = 0
    last_activity: str | None = None
    stats: dict[str, Any] | None = None  # implemented agents only (e.g. Monitor run totals)
    last_result: dict[str, Any] | None = None  # the last AgentResult (implemented agents only)
    llm: dict[str, Any] | None = None  # reasoning agents only: {"provider", "model", "configured"}


_AGENTS: tuple[tuple[AgentName, str, str, str], ...] = (
    (AgentName.MONITOR,
     "Ingests, validates, normalizes, deduplicates and correlates cloud events; opens incidents.",
     "Security events", "New IncidentState"),
    (AgentName.TRIAGE,
     "LLM-assisted, validated assessment of severity, priority, category and confidence; "
     "decides whether investigation is required.",
     "New IncidentState", "Triaged IncidentState"),
    (AgentName.INVESTIGATOR,
     "Reconstructs the attack chain, collects evidence and maps MITRE ATT&CK techniques.",
     "Triaged IncidentState", "Investigation + evidence"),
    (AgentName.COMPLIANCE,
     "Evaluates the incident and proposed actions against security policies and controls.",
     "Investigated IncidentState", "Compliance findings"),
    (AgentName.REMEDIATION,
     "Proposes allow-listed containment actions; executes only after human approval.",
     "Compliance-checked IncidentState", "Remediation plan + verification"),
)


def list_agents(tools: ToolRegistry, monitor_stats: dict[str, Any] | None = None,
                triage_stats: dict[str, Any] | None = None,
                triage_llm: dict[str, Any] | None = None) -> list[AgentDescriptor]:
    """Stats come from MonitorLedgerService.stats() / AgentRunService.stats() (None if
    unavailable); `triage_llm` describes the configured provider (never credentials)."""
    agents = []
    for name, purpose, inp, out in _AGENTS:
        descriptor = AgentDescriptor(agent_id=name.agent_id, name=name, purpose=purpose,
                                     input=inp, output=out, tools=tools.permissions_for(name))
        if name in IMPLEMENTED:
            descriptor.implemented = True
            descriptor.status = "idle"
            if name == AgentName.MONITOR and monitor_stats is not None:
                descriptor.tasks_processed = monitor_stats["events_processed"]
                descriptor.last_activity = monitor_stats["last_run_at"]
                descriptor.last_result = monitor_stats["last_result"]
                descriptor.stats = {k: v for k, v in monitor_stats.items() if k != "last_result"}
            if name == AgentName.TRIAGE:
                descriptor.llm = triage_llm
                if triage_stats is not None:
                    descriptor.tasks_processed = triage_stats["runs"]
                    descriptor.last_activity = triage_stats["last_run_at"]
                    descriptor.last_result = triage_stats["last_result"]
                    descriptor.stats = {k: v for k, v in triage_stats.items() if k != "last_result"}
        agents.append(descriptor)
    return agents
