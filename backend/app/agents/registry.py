"""Descriptions of the five agents and which are implemented.

Monitor, Triage, Investigator, Compliance and Remediation are implemented; the Verification stage is not an
agent yet. Permitted tools always come from the tool registry.
"""

from typing import Any, Literal

from pydantic import BaseModel

from app.domain.enums import AgentName
from app.tools.registry import ToolRegistry

AgentStatus = Literal["not_implemented", "idle", "running", "paused", "error"]

IMPLEMENTED = frozenset({AgentName.MONITOR, AgentName.TRIAGE, AgentName.INVESTIGATOR, AgentName.COMPLIANCE,
                         AgentName.REMEDIATION,
                         AgentName.VERIFICATION})
LLM_AGENTS = frozenset({AgentName.TRIAGE, AgentName.INVESTIGATOR, AgentName.COMPLIANCE, AgentName.REMEDIATION})


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
     "Evidence-first investigation: timeline, entities, attack sequence, findings and "
     "backend-validated MITRE ATT&CK techniques.",
     "Triaged IncidentState", "Investigated IncidentState"),
    (AgentName.COMPLIANCE,
     "Maps the investigated incident to configured security controls and framework requirements; "
     "separates control gaps from violations; states what is unknown. Not legal advice.",
     "Investigated IncidentState", "Compliance-assessed IncidentState"),
    (AgentName.REMEDIATION,
     "LLM-planned, policy-validated containment proposal. Executes an allow-listed action only after a human "
     "approves it, with the kill switch on, through the ToolExecutor.",
     "Compliance-assessed IncidentState", "Remediation proposal, approval and execution result"),
    (AgentName.VERIFICATION,
     "Read-only, deterministic check that the executed remediation achieved its expected security effect: "
     "compares the recorded BEFORE state, the EXPECTED state and the ACTUAL current state. Never executes or retries.",
     "Remediated IncidentState", "Verified / failed / partial / unknown IncidentState"),
)


def list_agents(tools: ToolRegistry, monitor_stats: dict[str, Any] | None = None,
                run_stats: dict[AgentName, dict[str, Any]] | None = None,
                llm: dict[str, Any] | None = None) -> list[AgentDescriptor]:
    """Stats come from MonitorLedgerService.stats() / AgentRunService.stats() (None if
    unavailable); `llm` describes the configured provider (never credentials)."""
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
            if name in LLM_AGENTS or name == AgentName.VERIFICATION:
                descriptor.llm = llm if name in LLM_AGENTS else None
                stats = (run_stats or {}).get(name)
                if stats is not None:
                    descriptor.tasks_processed = stats["runs"]
                    descriptor.last_activity = stats["last_run_at"]
                    descriptor.last_result = stats["last_result"]
                    descriptor.stats = {k: v for k, v in stats.items() if k != "last_result"}
        agents.append(descriptor)
    return agents
