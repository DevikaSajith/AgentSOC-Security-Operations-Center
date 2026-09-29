"""The minimal contract every AgentSOC agent implements.

An agent:
  * has a fixed `name` (an AgentName),
  * exposes `run(request) -> report`, where the report carries an AgentResult,
  * acts on the cloud only through app.tools.ToolExecutor (its permissions are enforced
    there), and writes what it did to the audit trail.
"""

from abc import ABC, abstractmethod
from typing import ClassVar, Generic, Protocol, TypeVar

from app.domain.agent_result import AgentResult
from app.domain.enums import AgentName


class AgentReport(Protocol):
    agent_result: AgentResult


RequestT = TypeVar("RequestT")
ReportT = TypeVar("ReportT", bound=AgentReport)


class BaseAgent(ABC, Generic[RequestT, ReportT]):
    name: ClassVar[AgentName]

    @abstractmethod
    def run(self, request: RequestT) -> ReportT:
        """Process one request. Must not raise for bad input: report it in the result."""
