"""
AgentSOC — Cloud Event Simulator

Generates realistic, structured sequences of cloud events for each attack scenario.
These events are passed to the Monitor Agent as if they came from real AWS services.

IMPORTANT: This simulator NEVER makes real AWS API calls.
"""

import uuid
from datetime import datetime, timedelta
from typing import List

from backend.schemas.models import CloudEvent, Severity


def _ts(offset_minutes: float = 0.0) -> str:
    """Return ISO timestamp offset from now."""
    t = datetime.utcnow() - timedelta(minutes=offset_minutes)
    return t.isoformat() + "Z"


def _evt_id() -> str:
    return f"EVT-{uuid.uuid4().hex[:8].upper()}"


# ============================================================
# Scenario: Credential Misuse / IAM Privilege Escalation
# ============================================================

def generate_credential_misuse_scenario() -> List[CloudEvent]:
    """
    Simulate a credential misuse / privilege escalation attack chain:
    1. Normal login (trusted IP)
    2. Login from unusual foreign IP (same user)
    3. CreateAccessKey (from foreign IP)
    4. IAM policy modification (AttachUserPolicy — AdministratorAccess)
    5. Sensitive S3 access (from new key)
    6. GetAccountAuthorizationDetails (discovery)
    """
    user = "m.ortiz"
    normal_ip = "192.168.1.100"
    malicious_ip = "103.21.244.19"  # Singapore
    resource_user = f"arn:aws:iam::482104872340:user/{user}"

    events = [
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(35),
            source="CloudTrail",
            event_type="ConsoleLogin",
            user=user,
            resource="us-east-1/console",
            source_ip=normal_ip,
            severity_hint=Severity.LOW,
            parameters={"mfa_used": True, "user_agent": "Mozilla/5.0"},
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(19),
            source="CloudTrail",
            event_type="ConsoleLogin",
            user=user,
            resource="ap-southeast-1/console",
            source_ip=malicious_ip,
            severity_hint=Severity.HIGH,
            parameters={
                "mfa_used": False,
                "user_agent": "python-requests/2.28",
                "impossible_travel": True,
                "distance_km": 15000,
            },
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(17),
            source="CloudTrail",
            event_type="CreateAccessKey",
            user=user,
            resource=resource_user,
            source_ip=malicious_ip,
            severity_hint=Severity.HIGH,
            parameters={
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "created_by_session": "suspicious",
            },
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(15),
            source="CloudTrail",
            event_type="AttachUserPolicy",
            user=user,
            resource=resource_user,
            source_ip=malicious_ip,
            severity_hint=Severity.CRITICAL,
            parameters={
                "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "policy_name": "AdministratorAccess",
            },
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(12),
            source="CloudTrail",
            event_type="GetObject",
            user=user,
            resource="s3://acme-prod-exports/customer_data_2025.csv",
            source_ip=malicious_ip,
            severity_hint=Severity.HIGH,
            parameters={
                "bucket": "acme-prod-exports",
                "key": "customer_data_2025.csv",
                "bytes_transferred": 48_000_000,
            },
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(10),
            source="CloudTrail",
            event_type="GetAccountAuthorizationDetails",
            user=user,
            resource="arn:aws:iam::482104872340:root",
            source_ip=malicious_ip,
            severity_hint=Severity.HIGH,
            parameters={"filter": ["User", "Role", "Group"]},
        ),
    ]

    return events


# ============================================================
# Scenario: IAM Privilege Escalation via CI Principal
# ============================================================

def generate_iam_privilege_escalation_scenario() -> List[CloudEvent]:
    """
    CI/CD pipeline credential abuse:
    1. AssumeRole by ci-deploy
    2. AttachUserPolicy (AdministratorAccess on self)
    3. ListUsers / GetAccountAuthorizationDetails (discovery)
    4. CreateAccessKey on root
    """
    user = "ci-deploy"
    source_ip = "185.41.72.19"
    resource_user = f"arn:aws:iam::482104872340:user/{user}"

    events = [
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(20),
            source="CloudTrail",
            event_type="AssumeRole",
            user=user,
            resource="arn:aws:iam::482104872340:role/DeployRunner",
            source_ip=source_ip,
            severity_hint=Severity.MEDIUM,
            parameters={"role_session_name": "deploy-session-001"},
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(18),
            source="CloudTrail",
            event_type="AttachUserPolicy",
            user=user,
            resource=resource_user,
            source_ip=source_ip,
            severity_hint=Severity.CRITICAL,
            parameters={
                "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "policy_name": "AdministratorAccess",
                "note": "CI principal attaching admin policy to itself",
            },
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(16),
            source="CloudTrail",
            event_type="GetAccountAuthorizationDetails",
            user=user,
            resource="arn:aws:iam::482104872340",
            source_ip=source_ip,
            severity_hint=Severity.HIGH,
            parameters={"filter": ["User", "Role"]},
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(14),
            source="GuardDuty",
            event_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
            user=user,
            resource=resource_user,
            source_ip=source_ip,
            severity_hint=Severity.CRITICAL,
            parameters={"finding_type": "InstanceCredentialExfiltration"},
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(12),
            source="CloudTrail",
            event_type="CreateAccessKey",
            user=user,
            resource=resource_user,
            source_ip=source_ip,
            severity_hint=Severity.HIGH,
            parameters={"access_key_id": "AKIAIOSFODNN7CI01"},
        ),
    ]

    return events


# ============================================================
# Scenario: Public S3 Exposure
# ============================================================

def generate_public_s3_scenario() -> List[CloudEvent]:
    """
    Production S3 bucket made public accidentally or maliciously.
    """
    user = "data-pipeline"
    source_ip = "52.94.18.204"

    events = [
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(30),
            source="Config",
            event_type="PutBucketPolicy",
            user=user,
            resource="acme-prod-exports",
            source_ip=source_ip,
            severity_hint=Severity.HIGH,
            parameters={
                "policy": '{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}',
                "bucket": "acme-prod-exports",
            },
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(28),
            source="Config",
            event_type="PutBucketAcl",
            user=user,
            resource="acme-prod-exports",
            source_ip=source_ip,
            severity_hint=Severity.HIGH,
            parameters={"acl": "public-read"},
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(25),
            source="CloudTrail",
            event_type="GetObject",
            user="ANONYMOUS",
            resource="s3://acme-prod-exports/customer_export_q4.csv",
            source_ip="203.0.113.42",
            severity_hint=Severity.CRITICAL,
            parameters={"anonymous_access": True, "bytes_transferred": 95_000_000},
        ),
    ]

    return events


# ============================================================
# Scenario: EC2 Command & Control
# ============================================================

def generate_ec2_c2_scenario() -> List[CloudEvent]:
    """
    EC2 instance beaconing to known C2 infrastructure.
    """
    events = [
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(45),
            source="VpcFlowLogs",
            event_type="NetworkConnection",
            user="ec2-role-prod",
            resource="i-0a73c9f8d2e1b4a9c",
            source_ip="10.42.7.18",
            severity_hint=Severity.HIGH,
            parameters={
                "destination_ip": "45.83.64.12",
                "destination_port": 8443,
                "protocol": "TCP",
                "direction": "outbound",
                "bytes_out": 1024,
                "known_c2": True,
            },
        ),
        CloudEvent(
            event_id=_evt_id(),
            timestamp=_ts(30),
            source="GuardDuty",
            event_type="Backdoor:EC2/C&CActivity.B",
            user="ec2-role-prod",
            resource="i-0a73c9f8d2e1b4a9c",
            source_ip="10.42.7.18",
            severity_hint=Severity.CRITICAL,
            parameters={"finding_type": "C&CActivity.B", "threat_intel_match": True},
        ),
    ]

    return events


# ============================================================
# Dispatcher
# ============================================================

SCENARIO_GENERATORS = {
    "credential_misuse": generate_credential_misuse_scenario,
    "iam": generate_iam_privilege_escalation_scenario,
    "s3": generate_public_s3_scenario,
    "ec2": generate_ec2_c2_scenario,
    # aliases
    "iam_privilege_escalation": generate_iam_privilege_escalation_scenario,
    "public_s3_exposure": generate_public_s3_scenario,
    "ec2_compromise": generate_ec2_c2_scenario,
}


def generate_scenario(scenario_type: str) -> List[CloudEvent]:
    """
    Generate a sequence of cloud events for a given scenario type.
    
    Raises ValueError for unknown scenarios.
    """
    generator = SCENARIO_GENERATORS.get(scenario_type)
    if not generator:
        raise ValueError(
            f"Unknown scenario: '{scenario_type}'. "
            f"Available: {list(SCENARIO_GENERATORS.keys())}"
        )
    events = generator()
    return events


def list_scenarios() -> List[str]:
    """Return the canonical list of unique scenario names."""
    return ["credential_misuse", "iam_privilege_escalation", "public_s3_exposure", "ec2_compromise"]
