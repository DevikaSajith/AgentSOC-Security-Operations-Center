"""
AgentSOC — Monitor Agent (Phase 2)

Responsibilities:
- Collect simulated cloud events
- Normalize events to CloudEvent schema
- Filter events by minimum severity
- Pass standardized events to Triage

The Monitor Agent does NOT perform complex reasoning.
Its only job is event collection and normalization.
"""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import yaml

from backend.schemas.models import (
    AgentName,
    AgentState,
    AuditEntry,
    CloudEvent,
    Severity,
    ToolCall,
    ToolResult,
)
from backend.tools.events.query_tools import get_recent_events

logger = logging.getLogger(__name__)


# ============================================================
# Event type severity hints
# (used when severity_hint is UNKNOWN)
# ============================================================

EVENT_TYPE_SEVERITY_MAP: Dict[str, Severity] = {
    "AttachUserPolicy": Severity.CRITICAL,
    "PutUserPolicy": Severity.CRITICAL,
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration": Severity.CRITICAL,
    "Backdoor:EC2/C&CActivity.B": Severity.CRITICAL,
    "CreateAccessKey": Severity.HIGH,
    "AssumeRole": Severity.MEDIUM,
    "ConsoleLogin": Severity.LOW,
    "GetObject": Severity.MEDIUM,
    "PutBucketPolicy": Severity.HIGH,
    "PutBucketAcl": Severity.HIGH,
    "NetworkConnection": Severity.HIGH,
    "GetAccountAuthorizationDetails": Severity.HIGH,
    "ListUsers": Severity.LOW,
    "ListBuckets": Severity.LOW,
    "DescribeInstances": Severity.LOW,
    "DeleteTrail": Severity.CRITICAL,
    "StopLogging": Severity.CRITICAL,
}


def normalize_event(event: CloudEvent) -> CloudEvent:
    """
    Normalize a CloudEvent:
    - Set severity_hint if UNKNOWN based on event_type
    - Validate required fields
    """
    if event.severity_hint == Severity.UNKNOWN:
        inferred = EVENT_TYPE_SEVERITY_MAP.get(event.event_type, Severity.UNKNOWN)
        # Create a new event with the inferred severity
        event = CloudEvent(
            **{**event.model_dump(), "severity_hint": inferred}
        )

    # GuardDuty events always get elevated
    if event.source == "GuardDuty" and event.severity_hint in (Severity.UNKNOWN, Severity.LOW):
        event = CloudEvent(**{**event.model_dump(), "severity_hint": Severity.HIGH})

    return event


def _load_agent_config() -> Dict:
    config_dir = os.environ.get(
        "CONFIG_DIR",
        os.path.join(os.path.dirname(__file__), "../../../config")
    )
    config_path = os.path.join(config_dir, "agent_config.yaml")
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def run_monitor(state: AgentState) -> AgentState:
    """
    Monitor Agent main execution function.
    
    Takes raw events from state, normalizes them, and updates state
    with normalized events and initial metadata.
    """
    start = datetime.utcnow()
    logger.info("[MONITOR] Starting. Input events: %d", len(state.raw_events))

    config = _load_agent_config().get("monitor", {})
    min_severity_str = config.get("min_severity_threshold", "low")
    severity_order = ["unknown", "low", "medium", "high", "critical"]

    min_idx = severity_order.index(min_severity_str) if min_severity_str in severity_order else 0

    # Step 1: Normalize all events
    normalized = [normalize_event(e) for e in state.raw_events]

    # Step 2: Filter by minimum severity
    filtered = [
        e for e in normalized
        if severity_order.index(e.severity_hint.value) >= min_idx
    ]

    logger.info("[MONITOR] Normalized %d events, %d pass severity filter", len(normalized), len(filtered))

    # Step 3: Record tool call
    tc = ToolCall(
        tool_name="get_recent_events",
        agent=AgentName.MONITOR,
        arguments={"count": len(normalized), "filtered": len(filtered)},
    )
    tr = ToolResult(
        tool_id=tc.tool_id,
        tool_name=tc.tool_name,
        success=True,
        data={"event_count": len(filtered)},
    )

    # Step 4: Audit entry
    end = datetime.utcnow()
    audit = AuditEntry(
        incident_id=state.incident_id,
        agent=AgentName.MONITOR,
        action=f"Collected and normalized {len(filtered)} security events",
        reasoning=f"Normalized {len(normalized)} raw events. {len(normalized) - len(filtered)} below {min_severity_str} threshold.",
        confidence=1.0,
        input_summary=f"{len(state.raw_events)} raw events from scenario '{state.scenario}'",
        tool_used=tc.tool_name,
        tool_result=tr.model_dump(),
        decision="PASS_TO_TRIAGE",
        result=f"{len(filtered)} events queued for triage",
    )

    logger.info("[MONITOR] Collected %d events in %.2fs", len(filtered), (end - start).total_seconds())

    return AgentState(
        **{
            **state.model_dump(),
            "raw_events": filtered,
            "event_ids": [e.event_id for e in filtered],
            "audit_entries": state.audit_entries + [audit],
        }
    )
