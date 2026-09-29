"""
AgentSOC — Event Query Tools

Provides structured query tools for agents to investigate cloud events.
Every tool produces a ToolCall + ToolResult for the audit trail.
All queries hit the local SQLite database populated by the simulator.
"""

import logging
from typing import Any, Dict, List, Optional

from backend.schemas.models import AgentName, ToolCall, ToolResult

logger = logging.getLogger(__name__)


def _make_result(tool_id: str, tool_name: str, data: Any, error: Optional[str] = None) -> ToolResult:
    return ToolResult(
        tool_id=tool_id,
        tool_name=tool_name,
        success=error is None,
        data=data,
        error=error,
    )


def get_user_activity(
    user: str,
    events: List[Dict],
    agent: AgentName = AgentName.INVESTIGATOR,
) -> tuple[ToolCall, ToolResult]:
    """Get all events attributed to a specific user."""
    call = ToolCall(
        tool_name="get_user_activity",
        agent=agent,
        arguments={"user": user},
    )
    try:
        user_events = [e for e in events if e.get("user") == user]
        return call, _make_result(call.tool_id, call.tool_name, {
            "user": user,
            "event_count": len(user_events),
            "events": user_events,
        })
    except Exception as e:
        return call, _make_result(call.tool_id, call.tool_name, None, str(e))


def get_recent_events(
    events: List[Dict],
    limit: int = 20,
    agent: AgentName = AgentName.MONITOR,
) -> tuple[ToolCall, ToolResult]:
    """Get the most recent cloud events (sorted by timestamp descending)."""
    call = ToolCall(
        tool_name="get_recent_events",
        agent=agent,
        arguments={"limit": limit},
    )
    try:
        sorted_events = sorted(
            events,
            key=lambda e: e.get("timestamp", ""),
            reverse=True,
        )[:limit]
        return call, _make_result(call.tool_id, call.tool_name, {
            "count": len(sorted_events),
            "events": sorted_events,
        })
    except Exception as e:
        return call, _make_result(call.tool_id, call.tool_name, None, str(e))


def get_resource_history(
    resource: str,
    events: List[Dict],
    agent: AgentName = AgentName.INVESTIGATOR,
) -> tuple[ToolCall, ToolResult]:
    """Get all events targeting a specific resource."""
    call = ToolCall(
        tool_name="get_resource_history",
        agent=agent,
        arguments={"resource": resource},
    )
    try:
        resource_events = [
            e for e in events
            if resource.lower() in e.get("resource", "").lower()
        ]
        return call, _make_result(call.tool_id, call.tool_name, {
            "resource": resource,
            "event_count": len(resource_events),
            "events": resource_events,
        })
    except Exception as e:
        return call, _make_result(call.tool_id, call.tool_name, None, str(e))


def get_related_events(
    event_id: str,
    events: List[Dict],
    agent: AgentName = AgentName.INVESTIGATOR,
) -> tuple[ToolCall, ToolResult]:
    """Find events related to a specific event (same user or source IP)."""
    call = ToolCall(
        tool_name="get_related_events",
        agent=agent,
        arguments={"event_id": event_id},
    )
    try:
        # Find the anchor event
        anchor = next((e for e in events if e.get("event_id") == event_id), None)
        if not anchor:
            return call, _make_result(call.tool_id, call.tool_name, None, f"Event {event_id} not found")

        # Find events with same user OR same source IP
        related = [
            e for e in events
            if e.get("event_id") != event_id and (
                e.get("user") == anchor.get("user")
                or e.get("source_ip") == anchor.get("source_ip")
            )
        ]
        return call, _make_result(call.tool_id, call.tool_name, {
            "anchor_event_id": event_id,
            "anchor_user": anchor.get("user"),
            "anchor_ip": anchor.get("source_ip"),
            "related_count": len(related),
            "related_events": related,
        })
    except Exception as e:
        return call, _make_result(call.tool_id, call.tool_name, None, str(e))


def get_identity_history(
    user: str,
    events: List[Dict],
    agent: AgentName = AgentName.INVESTIGATOR,
) -> tuple[ToolCall, ToolResult]:
    """Reconstruct identity access pattern including IPs, event types, and timeline."""
    call = ToolCall(
        tool_name="get_identity_history",
        agent=agent,
        arguments={"user": user},
    )
    try:
        user_events = sorted(
            [e for e in events if e.get("user") == user],
            key=lambda e: e.get("timestamp", ""),
        )
        ips = list({e.get("source_ip") for e in user_events if e.get("source_ip")})
        event_types = list({e.get("event_type") for e in user_events if e.get("event_type")})

        # Check for impossible travel
        impossible_travel = any(
            e.get("parameters", {}).get("impossible_travel") for e in user_events
        )

        return call, _make_result(call.tool_id, call.tool_name, {
            "user": user,
            "event_count": len(user_events),
            "source_ips": ips,
            "event_types": event_types,
            "impossible_travel": impossible_travel,
            "timeline": user_events,
        })
    except Exception as e:
        return call, _make_result(call.tool_id, call.tool_name, None, str(e))


def get_network_context(
    source_ip: str,
    events: List[Dict],
    agent: AgentName = AgentName.INVESTIGATOR,
) -> tuple[ToolCall, ToolResult]:
    """Get all events from a specific source IP and IP reputation context."""
    call = ToolCall(
        tool_name="get_network_context",
        agent=agent,
        arguments={"source_ip": source_ip},
    )
    try:
        ip_events = [e for e in events if e.get("source_ip") == source_ip]

        # Heuristic: IPs outside RFC1918 with high-severity events are suspicious
        is_private = (
            source_ip.startswith("10.") or
            source_ip.startswith("192.168.") or
            source_ip.startswith("172.")
        )
        suspicious_indicators = [
            e.get("event_type") for e in ip_events
            if e.get("severity_hint") in ("high", "critical")
        ]

        return call, _make_result(call.tool_id, call.tool_name, {
            "source_ip": source_ip,
            "is_private": is_private,
            "event_count": len(ip_events),
            "suspicious_event_types": suspicious_indicators,
            "reputation": "suspicious" if (not is_private and suspicious_indicators) else "unknown",
            "events": ip_events,
        })
    except Exception as e:
        return call, _make_result(call.tool_id, call.tool_name, None, str(e))


def get_attack_sequence(
    events: List[Dict],
    agent: AgentName = AgentName.INVESTIGATOR,
) -> tuple[ToolCall, ToolResult]:
    """
    Reconstruct a chronological attack sequence from the given events.
    Groups by user and sorts by timestamp.
    """
    call = ToolCall(
        tool_name="get_attack_sequence",
        agent=agent,
        arguments={},
    )
    try:
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        chain = []
        for e in sorted_events:
            chain.append({
                "timestamp": e.get("timestamp"),
                "event_type": e.get("event_type"),
                "user": e.get("user"),
                "resource": e.get("resource"),
                "source_ip": e.get("source_ip"),
                "severity_hint": e.get("severity_hint"),
            })

        return call, _make_result(call.tool_id, call.tool_name, {
            "event_count": len(chain),
            "sequence": chain,
        })
    except Exception as e:
        return call, _make_result(call.tool_id, call.tool_name, None, str(e))
