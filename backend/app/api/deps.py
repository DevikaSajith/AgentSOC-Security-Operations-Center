"""FastAPI dependencies: access to the app's singletons and per-request DB sessions."""

import logging
from typing import Iterator

from fastapi import HTTPException, Request
from sqlalchemy.exc import SQLAlchemyError

from app.agents.compliance.agent import ComplianceAgent
from app.agents.investigator.agent import InvestigatorAgent
from app.agents.monitor.agent import MonitorAgent
from app.agents.remediation.agent import RemediationAgent
from app.agents.remediation.execution import RemediationExecutor
from app.agents.verification.agent import VerificationAgent
from app.agents.triage.agent import TriageAgent
from app.database.connection import Database
from app.domain.incident import AuditEntry
from app.services.audit_service import AuditService
from app.services.errors import DatabaseUnavailableError
from app.services.event_service import EventService
from app.services.incident_service import IncidentService
from app.simulator.attacks import AttackSimulator
from app.simulator.cloud import CloudSimulator
from app.tools.base import ToolContext
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


def get_cloud(request: Request) -> CloudSimulator:
    return request.app.state.cloud


def get_attacks(request: Request) -> AttackSimulator:
    return request.app.state.attacks


def get_tool_registry(request: Request) -> ToolRegistry:
    return request.app.state.tools


def ready_database(request: Request) -> Database:
    """The app's Database with its schema created, or a 503-mapped error."""
    database: Database | None = request.app.state.database
    if database is None:
        raise DatabaseUnavailableError("database is not configured")
    try:
        database.ensure_schema()
    except SQLAlchemyError as exc:
        logger.error("database unavailable: %s", type(exc).__name__)
        raise DatabaseUnavailableError("database is unavailable") from exc
    return database


def get_event_service(request: Request) -> Iterator[EventService]:
    with ready_database(request).session() as session:
        yield EventService(session)


def get_incident_service(request: Request) -> Iterator[IncidentService]:
    with ready_database(request).session() as session:
        yield IncidentService(session)


def get_audit_service(request: Request) -> Iterator[AuditService]:
    with ready_database(request).session() as session:
        yield AuditService(session)


def record_audit(request: Request, entry: AuditEntry) -> None:
    """Write one audit entry in its own session (never fails the caller's request)."""
    try:
        with ready_database(request).session() as session:
            AuditService(session).record(entry)
    except Exception:
        logger.exception("could not record audit entry %s", entry.action)


def get_monitor_agent(request: Request) -> MonitorAgent:
    """A Monitor Agent wired to the app's database, rules, tools and audit trail."""
    config = request.app.state.monitor_config
    if config is None:
        raise HTTPException(503, "Monitor Agent unavailable: monitor_rules.yaml missing or invalid")
    return MonitorAgent(ready_database(request), config, get_tool_executor(request),
                        audit_sink=lambda entry: record_audit(request, entry))


def get_triage_agent(request: Request) -> TriageAgent:
    """A Triage Agent wired to the database, triage rules, LLM provider, tools and audit."""
    config = request.app.state.triage_config
    if config is None:
        raise HTTPException(503, "Triage Agent unavailable: triage_rules.yaml missing or invalid")
    return TriageAgent(ready_database(request), config, request.app.state.llm,
                       get_tool_executor(request),
                       audit_sink=lambda entry: record_audit(request, entry))


def get_investigator_agent(request: Request) -> InvestigatorAgent:
    """An Investigator Agent wired to the database, rules, LLM provider, tools and audit."""
    config = request.app.state.investigator_config
    if config is None:
        raise HTTPException(503, "Investigator Agent unavailable: investigator_rules.yaml missing or invalid")
    return InvestigatorAgent(ready_database(request), config, request.app.state.llm,
                             get_tool_executor(request),
                             audit_sink=lambda entry: record_audit(request, entry),
                             config_dir=request.app.state.settings.config_dir)


def get_compliance_agent(request: Request) -> ComplianceAgent:
    """A Compliance Agent wired to the database, configured mappings, LLM provider, tools and audit."""
    settings = request.app.state.compliance_settings
    if settings is None:
        raise HTTPException(503, "Compliance Agent unavailable: compliance_mapping.yaml / "
                                 "compliance_policy.yaml missing or invalid")
    return ComplianceAgent(ready_database(request), settings, request.app.state.llm,
                           get_tool_executor(request),
                           audit_sink=lambda entry: record_audit(request, entry))


def get_remediation_agent(request: Request) -> RemediationAgent:
    """A Remediation (planning) Agent: LLM provider + policy + tools + audit. It never executes anything."""
    policy = request.app.state.remediation_settings
    if policy is None:
        raise HTTPException(503, "Remediation Agent unavailable: remediation_policy.yaml missing or invalid")
    return RemediationAgent(ready_database(request), policy, request.app.state.llm,
                            get_tool_executor(request),
                            audit_sink=lambda entry: record_audit(request, entry))


def get_remediation_executor(request: Request) -> RemediationExecutor:
    """Executes ONE already-requested approval: human decision -> gates -> kill switch -> ToolExecutor."""
    policy = request.app.state.remediation_settings
    if policy is None:
        raise HTTPException(503, "Remediation unavailable: remediation_policy.yaml missing or invalid")
    return RemediationExecutor(ready_database(request), policy, get_tool_executor(request),
                               audit_sink=lambda entry: record_audit(request, entry))


def get_verification_agent(request: Request) -> VerificationAgent:
    """A read-only, deterministic Verification Agent (no LLM, no action tools, no approval access)."""
    rules = request.app.state.verification_rules
    if rules is None:
        raise HTTPException(503, "Verification Agent unavailable: verification_rules.yaml missing or invalid")
    return VerificationAgent(ready_database(request), rules, get_tool_executor(request),
                             audit_sink=lambda entry: record_audit(request, entry))


def get_tool_executor(request: Request) -> ToolExecutor:
    context = ToolContext(cloud=request.app.state.cloud, database=request.app.state.database,
                          registry=request.app.state.tools,
                          config_dir=request.app.state.settings.config_dir)
    return ToolExecutor(context, audit_sink=lambda entry: record_audit(request, entry))
