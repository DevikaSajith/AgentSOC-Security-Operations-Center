"""
AgentSOC — Common Pydantic Data Models (Phase 1)

Strict typed models shared across all agents and tools.
These serve as the data contracts for inter-agent communication.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ============================================================
# Enumerations
# ============================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IncidentStatus(str, Enum):
    DETECTING = "Detecting"
    INVESTIGATING = "Investigating"
    AWAITING_APPROVAL = "Awaiting approval"
    REMEDIATING = "Remediating"
    CONTAINED = "Contained"
    RESOLVED = "Resolved"
    REJECTED = "Rejected"


class ApprovalStatus(str, Enum):
    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    AUTO_APPROVED = "Auto-approved"


class AgentName(str, Enum):
    MONITOR = "MonitorAgent"
    TRIAGE = "TriageAgent"
    INVESTIGATOR = "InvestigatorAgent"
    COMPLIANCE = "ComplianceAgent"
    REMEDIATION = "RemediationAgent"
    SYSTEM = "System"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RemediationStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    FAILED = "failed"
    SKIPPED = "skipped"


# ============================================================
# Core Cloud Event
# ============================================================

class CloudEvent(BaseModel):
    """
    Normalized representation of a single cloud activity event.
    This is the primary input to the Monitor Agent.
    """
    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:8]}")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    source: str  # "CloudTrail", "GuardDuty", "VpcFlowLogs", "Config"
    event_type: str  # "CreateAccessKey", "AttachUserPolicy", "ConsoleLogin", etc.
    user: str
    resource: str
    source_ip: str = "unknown"
    region: str = "us-east-1"
    parameters: Dict[str, Any] = Field(default_factory=dict)
    severity_hint: Severity = Severity.UNKNOWN
    raw: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_id")
    @classmethod
    def normalize_event_id(cls, v: str) -> str:
        return v.upper() if v.startswith("evt_") else v


# ============================================================
# Tool Call / Result
# ============================================================

class ToolCall(BaseModel):
    """Record of a tool invocation by an agent."""
    tool_id: str = Field(default_factory=lambda: f"tc_{uuid.uuid4().hex[:8]}")
    tool_name: str
    agent: AgentName
    incident_id: Optional[str] = None
    arguments: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ToolResult(BaseModel):
    """Structured result from a tool invocation."""
    tool_id: str
    tool_name: str
    success: bool
    data: Any = None
    error: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ============================================================
# Agent Decision
# ============================================================

class AgentDecision(BaseModel):
    """A structured decision made by an agent."""
    decision_id: str = Field(default_factory=lambda: f"dec_{uuid.uuid4().hex[:8]}")
    agent: AgentName
    incident_id: Optional[str]
    decision: str  # e.g., "INVESTIGATE", "ESCALATE", "ALLOW", "BLOCK"
    reasoning: str
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ============================================================
# Incident
# ============================================================

class Incident(BaseModel):
    """
    A security incident derived from correlated cloud events.
    Mirrors the frontend Incident type shape.
    """
    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:6].upper()}")
    title: str
    severity: Severity = Severity.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    incident_type: str  # "Credential Compromise", "Privilege Escalation", etc.
    source: str = "CloudTrail"
    resource: str = ""
    user: str = ""
    source_ip: str = "unknown"
    status: IncidentStatus = IncidentStatus.DETECTING
    current_agent: AgentName = AgentName.MONITOR
    created: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    related_event_ids: List[str] = Field(default_factory=list)
    description: str = ""
    reasoning: str = ""
    recommended_next_step: str = "investigate"


# ============================================================
# Triage Result
# ============================================================

class TriageResult(BaseModel):
    """Output from the Triage Agent."""
    incident_id: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    incident_type: str
    related_events: List[str] = Field(default_factory=list)
    reasoning: str
    recommended_next_step: str  # "investigate", "monitor", "close"
    mitre_hints: List[str] = Field(default_factory=list)


# ============================================================
# Investigation Result
# ============================================================

class MitreTechnique(BaseModel):
    technique_id: str   # "T1098"
    technique_name: str
    tactic: str         # "Privilege Escalation"
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[str] = Field(default_factory=list)


class InvestigationResult(BaseModel):
    """Output from the Investigator Agent."""
    incident_id: str
    attack_stage: str
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    attack_chain: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    investigation_summary: str
    proposed_action: str  # "disable_access_key", "isolate_instance", etc.
    proposed_action_target: str


# ============================================================
# Compliance Result
# ============================================================

class ComplianceResult(BaseModel):
    """Output from the Compliance Agent."""
    incident_id: str
    allowed: bool
    risk: RiskLevel
    approval_required: bool
    policy_id: str
    reason: str
    proposed_action: str
    proposed_action_target: str


# ============================================================
# Remediation
# ============================================================

class RemediationAction(BaseModel):
    """An approved remediation action to execute."""
    action_id: str = Field(default_factory=lambda: f"rem_{uuid.uuid4().hex[:8]}")
    incident_id: str
    action_type: str  # "disable_access_key", "isolate_instance", etc.
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    approved_by: str = "auto"
    approval_id: Optional[str] = None


class RemediationResult(BaseModel):
    """Result of a remediation action execution."""
    action_id: str
    incident_id: str
    action_type: str
    target: str
    status: RemediationStatus
    before_state: Optional[Dict[str, Any]] = None
    after_state: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    verification_status: VerificationStatus = VerificationStatus.SKIPPED
    verification_detail: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ============================================================
# Approval
# ============================================================

class ApprovalRequest(BaseModel):
    """A pending approval request in the human approval gate."""
    approval_id: str = Field(default_factory=lambda: f"APR-{uuid.uuid4().hex[:6].upper()}")
    incident_id: str
    action: str
    resource: str
    reason: str
    requested_by: AgentName
    risk: RiskLevel
    status: ApprovalStatus = ApprovalStatus.PENDING
    policy_id: str
    created: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    decided_by: Optional[str] = None
    decided_at: Optional[str] = None


# ============================================================
# Audit Log Entry
# ============================================================

class AuditEntry(BaseModel):
    """
    Immutable audit record created by every agent.
    Persisted to SQLite.
    """
    audit_id: str = Field(default_factory=lambda: f"aud_{uuid.uuid4().hex[:8]}")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    incident_id: Optional[str] = None
    agent: AgentName
    action: str
    reasoning: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    input_summary: str = ""
    tool_used: Optional[str] = None
    tool_result: Optional[Dict[str, Any]] = None
    decision: str
    result: str


# ============================================================
# Agent State (LangGraph TypedDict basis)
# ============================================================

class AgentState(BaseModel):
    """
    Shared state passed through the LangGraph workflow.
    All agents read from and write to this state.
    """
    # Input
    scenario: str = ""
    raw_events: List[CloudEvent] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)

    # Incident
    incident_id: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    confidence: float = 0.0
    incident_type: str = ""

    # Triage
    triage_result: Optional[TriageResult] = None

    # Investigation
    investigation: Optional[InvestigationResult] = None
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    attack_chain: List[str] = Field(default_factory=list)

    # Compliance
    proposed_action: str = ""
    proposed_action_target: str = ""
    compliance_result: Optional[ComplianceResult] = None
    approval_required: bool = False
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approval_id: Optional[str] = None

    # Remediation
    remediation_result: Optional[RemediationResult] = None

    # Audit
    audit_entries: List[AuditEntry] = Field(default_factory=list)

    # Workflow control
    error: Optional[str] = None
    completed: bool = False
