"""AgentResult: the structured output every agent must return."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.domain.enums import AgentName, AgentRunStatus
from app.domain.events import utcnow
from app.domain.incident import Evidence


class ProposedAction(BaseModel):
    """A structured tool action an agent *requests*. It is never executed directly:
    it must go through the tool layer (validation -> permission -> approval)."""

    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""


class AgentAction(BaseModel):
    """Something the agent *did* during its run (e.g. created or updated an incident)."""

    action: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_]*$")  # create_incident, ...
    target: str | None = None  # e.g. the incident ID
    details: dict[str, Any] = Field(default_factory=dict)


class AgentResult(BaseModel):
    """Output of one agent run.

    `incident_id` is None only when the run did not touch exactly one incident
    (e.g. a batch run that created none, or several - see `actions`).
    `outcome` is an agent-specific machine-readable label, e.g. 'incident_created'.
    """

    agent_name: AgentName
    incident_id: str | None = None
    status: AgentRunStatus
    outcome: str = Field(default="", pattern=r"^[a-z_]*$")
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning_summary: str = ""
    findings: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    actions: list[AgentAction] = Field(default_factory=list)
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _failed_runs_explain_themselves(self) -> "AgentResult":
        if self.status == AgentRunStatus.FAILED and not self.errors:
            raise ValueError("a failed AgentResult must list at least one error")
        return self
