"""Tool contracts.

Every capability an agent (or analyst) can use is a *tool*: a named, deterministic
Python function with a Pydantic input model. There is no generic "run a command" tool.

    Structured action (ToolRequest)
      -> Pydantic validation of the arguments  (ToolInput, extra fields rejected)
      -> tool permission check                 (ToolRegistry permission matrix)
      -> approval check                        (ACTION tools only)
      -> deterministic tool handler            (read tools / simulator actions)

READ tools only observe. ACTION tools change (simulated) cloud state and always need
a human decision.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.domain.enums import ApprovalStatus, HumanActor, Severity
from app.domain.events import utcnow
from app.domain.incident import Actor

if TYPE_CHECKING:
    from app.database.connection import Database
    from app.simulator.cloud import CloudSimulator
    from app.tools.registry import ToolRegistry

# Identifiers accepted by tools: no whitespace, quotes, shell or path-traversal characters.
SafeIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128,
                           pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@/+=-]*$")]


class ToolKind(str, Enum):
    READ = "read"
    ACTION = "action"


class ToolInput(BaseModel):
    """Base class for every tool's argument model. Unknown arguments are rejected."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolError(Exception):
    """Raised by a tool handler for an expected failure (e.g. resource not found)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class ToolContext:
    """What handlers may use. Handlers never receive raw request data."""

    cloud: "CloudSimulator"
    database: "Database | None"
    registry: "ToolRegistry"
    config_dir: Path


Handler = Callable[[ToolContext, Any], Any]


@dataclass(frozen=True)
class ToolSpec:
    """Static description of one tool."""

    name: str
    kind: ToolKind
    description: str
    input_model: type[ToolInput]
    handler: Handler = field(repr=False)
    risk: Severity = Severity.LOW
    reversible: bool = True

    @property
    def requires_approval(self) -> bool:
        """Every ACTION tool requires a human decision; READ tools never do."""
        return self.kind == ToolKind.ACTION

    def describe(self) -> dict[str, Any]:
        """JSON-friendly description (used by GET /api/tools and check_policy)."""
        return {
            "name": self.name,
            "kind": self.kind.value,
            "description": self.description,
            "risk": self.risk.value,
            "reversible": self.reversible,
            "requires_approval": self.requires_approval,
            "input_schema": self.input_model.model_json_schema(),
        }


class ApprovalGrant(BaseModel):
    """Evidence that a human approved a specific action for a specific incident."""

    approval_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    status: ApprovalStatus
    decided_by: str = Field(min_length=1)
    decided_at: datetime = Field(default_factory=utcnow)


class ToolRequest(BaseModel):
    """A structured action: the ONLY way anything (LLM output included) can invoke a tool."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: f"TR-{uuid4().hex[:10].upper()}")
    tool_name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    requested_by: Actor
    incident_id: str | None = None
    approval: ApprovalGrant | None = None
    reason: str = Field(default="", max_length=2000)

    @property
    def is_human(self) -> bool:
        return self.requested_by == HumanActor.ANALYST


ToolOutcome = Literal["succeeded", "denied", "invalid", "failed"]


class ToolExecutionResult(BaseModel):
    """What happened to a ToolRequest. Every request produces one (and an audit entry)."""

    request_id: str
    tool_name: str
    kind: ToolKind | None = None
    requested_by: Actor
    incident_id: str | None = None
    outcome: ToolOutcome
    error_code: str | None = None  # unknown_tool, invalid_arguments, permission_denied, ...
    error: str | None = None
    output: Any = None
    timestamp: datetime = Field(default_factory=utcnow)

    @property
    def ok(self) -> bool:
        return self.outcome == "succeeded"
