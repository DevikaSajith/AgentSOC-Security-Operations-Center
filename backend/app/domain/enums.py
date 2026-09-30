"""Enumerations shared by the whole backend (API, services, tools and future agents)."""

from enum import Enum


class Severity(str, Enum):
    """Severity of an event or incident, ordered from most to least severe."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Priority(str, Enum):
    """Response priority assigned during triage (P1 = act now)."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class IncidentCategory(str, Enum):
    """Which part of the cloud an incident is about (initially set by the Monitor Agent
    from deterministic event/resource rules; later agents may refine it)."""

    IAM = "iam"
    S3 = "s3"
    EC2 = "ec2"
    NETWORK = "network"
    CREDENTIAL = "credential"
    OTHER = "other"


class IncidentStatus(str, Enum):
    """Lifecycle status of an incident (IncidentState.final_status)."""

    NEW = "new"
    TRIAGING = "triaging"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    INVESTIGATED = "investigated"
    COMPLIANCE_ASSESSED = "compliance_assessed"
    REMEDIATION_PENDING = "remediation_pending"
    REMEDIATION_APPROVED = "remediation_approved"
    REMEDIATION_REJECTED = "remediation_rejected"
    REMEDIATION_FAILED = "remediation_failed"
    REMEDIATED = "remediated"
    VERIFIED = "verified"
    VERIFICATION_FAILED = "verification_failed"
    PARTIAL_REMEDIATION = "partial_remediation"
    VERIFICATION_UNKNOWN = "verification_unknown"
    AWAITING_APPROVAL = "awaiting_approval"
    REMEDIATING = "remediating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    FAILED = "failed"


class ApprovalStatus(str, Enum):
    """State of the human approval gate for a remediation plan."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class RemediationStatus(str, Enum):
    """Progress of a remediation plan or step."""

    NOT_STARTED = "not_started"
    PROPOSED = "proposed"
    IN_PROGRESS = "in_progress"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class VerificationStatus(str, Enum):
    """Whether a remediation was confirmed by re-reading cloud state."""

    NOT_VERIFIED = "not_verified"
    VERIFIED = "verified"
    FAILED = "failed"


class AgentName(str, Enum):
    """The six AgentSOC agents. These display names are used everywhere."""

    MONITOR = "Monitor Agent"
    TRIAGE = "Triage Agent"
    INVESTIGATOR = "Investigator Agent"
    COMPLIANCE = "Compliance Agent"
    REMEDIATION = "Remediation Agent"
    VERIFICATION = "Verification Agent"

    @property
    def agent_id(self) -> str:
        """Short, URL-safe id: 'monitor', 'triage', ..."""
        return self.name.lower()


class HumanActor(str, Enum):
    """Non-agent actors that can appear in decisions, audit entries and tool calls."""

    ANALYST = "Human Analyst"
    SYSTEM = "System"


class AgentRunStatus(str, Enum):
    """Outcome of one agent run (AgentResult.status)."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class TriageNextStep(str, Enum):
    """The only workflow recommendations Triage may make."""

    INVESTIGATE = "investigate"
    ESCALATE = "escalate"
    MONITOR = "monitor"
    CLOSE = "close"


class TriageMethod(str, Enum):
    """How a triage decision was produced. A fallback is never presented as an LLM decision."""

    LLM = "llm"
    RULE_BASED_FALLBACK = "rule_based_fallback"


class EventSource(str, Enum):
    """Telemetry sources the simulator imitates (no real AWS is contacted)."""

    GUARDDUTY = "GuardDuty"
    CLOUDTRAIL = "CloudTrail"
    SECURITY_HUB = "Security Hub"
    VPC_FLOW_LOGS = "VPC Flow Logs"
    IAM = "IAM"
    EC2 = "EC2"
    S3 = "S3"


# Names used by earlier versions of the frontend. Accepted on input only.
LEGACY_AGENT_NAMES: dict[str, AgentName] = {
    "Detection Agent": AgentName.MONITOR,
    "Investigation Agent": AgentName.INVESTIGATOR,
    "Validation Agent": AgentName.COMPLIANCE,
    "Response Agent": AgentName.REMEDIATION,
    "MonitorAgent": AgentName.MONITOR,
    "TriageAgent": AgentName.TRIAGE,
    "InvestigatorAgent": AgentName.INVESTIGATOR,
    "ComplianceAgent": AgentName.COMPLIANCE,
    "RemediationAgent": AgentName.REMEDIATION,
    "VerificationAgent": AgentName.VERIFICATION,
}


def normalize_agent_name(value: str) -> AgentName:
    """Map a current name, an agent id ('triage') or a legacy name to an AgentName."""
    for agent in AgentName:
        if value in (agent.value, agent.agent_id):
            return agent
    if value in LEGACY_AGENT_NAMES:
        return LEGACY_AGENT_NAMES[value]
    raise ValueError(f"unknown agent '{value}'")
