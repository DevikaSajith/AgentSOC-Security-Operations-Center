"""
AgentSOC — Triage Agent Rule-Based Fallback

Deterministic triage rules that run when:
1. The LLM is unavailable
2. The LLM returns invalid output after max retries
3. LLM mode is disabled in config

This fallback is also used for the "Rule-Based SOAR" baseline comparison.
"""

from typing import List

from backend.schemas.models import CloudEvent, Severity, TriageResult


# ============================================================
# Rule Pattern Definitions
# ============================================================

class TriageRule:
    def __init__(self, rule_id: str, name: str, incident_type: str,
                 severity: Severity, required_events: List[str],
                 confidence: float, reasoning: str, mitre_hints: List[str] = None):
        self.rule_id = rule_id
        self.name = name
        self.incident_type = incident_type
        self.severity = severity
        self.required_events = required_events
        self.confidence = confidence
        self.reasoning = reasoning
        self.mitre_hints = mitre_hints or []

    def matches(self, event_types: List[str], has_impossible_travel: bool = False) -> bool:
        """Returns True if any required event type is present in the event stream."""
        event_set = set(event_types)
        required_set = set(self.required_events)
        return bool(event_set.intersection(required_set))

    def compute_confidence(self, event_types: List[str], has_impossible_travel: bool = False) -> float:
        """Compute confidence based on how many required events are present."""
        event_set = set(event_types)
        required_set = set(self.required_events)
        overlap = len(event_set.intersection(required_set))
        coverage = overlap / max(len(required_set), 1)
        conf = self.confidence * (0.6 + coverage * 0.4)
        if has_impossible_travel and self.incident_type == "Credential Compromise":
            conf = min(conf + 0.15, 1.0)
        return round(min(conf, 1.0), 3)


TRIAGE_RULES: List[TriageRule] = [
    TriageRule(
        rule_id="RULE-001",
        name="IAM Privilege Escalation",
        incident_type="IAM Privilege Escalation",
        severity=Severity.CRITICAL,
        required_events=["AttachUserPolicy", "PutUserPolicy", "AddUserToGroup"],
        confidence=0.92,
        reasoning="A principal modified its own or another user's IAM permissions. This is a strong indicator of privilege escalation.",
        mitre_hints=["T1098", "T1078"],
    ),
    TriageRule(
        rule_id="RULE-002",
        name="Credential Compromise — Access Key Creation",
        incident_type="Credential Compromise",
        severity=Severity.HIGH,
        required_events=["CreateAccessKey"],
        confidence=0.75,
        reasoning="An access key was created. When combined with login from unusual IP, this indicates credential compromise.",
        mitre_hints=["T1098", "T1078"],
    ),
    TriageRule(
        rule_id="RULE-003",
        name="Credential Compromise — Impossible Travel",
        incident_type="Credential Compromise",
        severity=Severity.HIGH,
        required_events=["ConsoleLogin"],
        confidence=0.78,
        reasoning="A user logged in from geographically distant locations within a short timeframe (impossible travel).",
        mitre_hints=["T1078"],
    ),
    TriageRule(
        rule_id="RULE-004",
        name="EC2 Command and Control",
        incident_type="Command and Control",
        severity=Severity.HIGH,
        required_events=["NetworkConnection", "Backdoor:EC2/C&CActivity.B"],
        confidence=0.88,
        reasoning="An EC2 instance initiated outbound network connections to known command-and-control infrastructure.",
        mitre_hints=["T1071"],
    ),
    TriageRule(
        rule_id="RULE-005",
        name="Public S3 Bucket Exposure",
        incident_type="Public Cloud Exposure",
        severity=Severity.HIGH,
        required_events=["PutBucketPolicy", "PutBucketAcl"],
        confidence=0.85,
        reasoning="An S3 bucket policy or ACL was modified to allow public access. Sensitive data may be exposed.",
        mitre_hints=["T1530"],
    ),
    TriageRule(
        rule_id="RULE-006",
        name="GuardDuty Critical Finding",
        incident_type="Credential Compromise",
        severity=Severity.CRITICAL,
        required_events=[
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
            "Backdoor:EC2/C&CActivity.B",
        ],
        confidence=0.95,
        reasoning="GuardDuty reported a critical finding indicating active unauthorized access or credential exfiltration.",
        mitre_hints=["T1078", "T1098"],
    ),
    TriageRule(
        rule_id="RULE-007",
        name="Cloud Infrastructure Discovery",
        incident_type="Reconnaissance",
        severity=Severity.MEDIUM,
        required_events=["GetAccountAuthorizationDetails", "ListUsers", "ListBuckets", "DescribeInstances"],
        confidence=0.60,
        reasoning="Enumeration of cloud infrastructure resources was observed, suggesting reconnaissance activity.",
        mitre_hints=["T1580"],
    ),
    TriageRule(
        rule_id="RULE-008",
        name="Defense Evasion — Logging Disabled",
        incident_type="Defense Evasion",
        severity=Severity.CRITICAL,
        required_events=["DeleteTrail", "StopLogging"],
        confidence=0.95,
        reasoning="CloudTrail logging was stopped or deleted, indicating an attempt to hide malicious activity.",
        mitre_hints=["T1562"],
    ),
]


def rule_based_triage(
    events: List[CloudEvent],
    incident_id: str,
) -> TriageResult:
    """
    Apply deterministic triage rules to classify an incident.
    
    Returns a TriageResult using the highest-confidence matching rule.
    Falls back to LOW severity if no rule matches.
    """
    event_types = [e.event_type for e in events]
    has_impossible_travel = any(
        e.parameters.get("impossible_travel") for e in events
    )

    best_rule: TriageRule = None
    best_confidence = 0.0

    for rule in TRIAGE_RULES:
        if rule.matches(event_types, has_impossible_travel):
            conf = rule.compute_confidence(event_types, has_impossible_travel)
            if conf > best_confidence:
                best_confidence = conf
                best_rule = rule

    if best_rule is None:
        # No rule matched — low severity
        return TriageResult(
            incident_id=incident_id,
            severity=Severity.LOW,
            confidence=0.15,
            incident_type="Unknown",
            related_events=[e.event_id for e in events],
            reasoning="No triage rule matched the observed event patterns. Flagging for low-priority review.",
            recommended_next_step="monitor",
            mitre_hints=[],
        )

    # Escalate severity if impossible travel confirmed
    severity = best_rule.severity
    if has_impossible_travel and severity == Severity.MEDIUM:
        severity = Severity.HIGH

    # Find related events (those whose type matches the rule's required events)
    required_set = set(best_rule.required_events)
    related = [e.event_id for e in events if e.event_type in required_set]
    if not related:
        related = [e.event_id for e in events]

    # Recommend next step based on severity
    if severity in (Severity.CRITICAL, Severity.HIGH):
        next_step = "investigate"
    elif severity == Severity.MEDIUM and best_confidence > 0.5:
        next_step = "investigate"
    else:
        next_step = "monitor"

    return TriageResult(
        incident_id=incident_id,
        severity=severity,
        confidence=best_confidence,
        incident_type=best_rule.incident_type,
        related_events=related,
        reasoning=best_rule.reasoning,
        recommended_next_step=next_step,
        mitre_hints=best_rule.mitre_hints,
    )
