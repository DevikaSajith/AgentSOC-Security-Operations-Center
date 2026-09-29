"""
AgentSOC — MITRE ATT&CK Lookup Tool

Maps observed cloud events to MITRE ATT&CK techniques using the
config/mitre_mapping.yaml knowledge base.

IMPORTANT: Only maps techniques when the observed evidence supports it.
Never hallucinate technique mappings.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import yaml

from backend.schemas.models import AgentName, MitreTechnique, ToolCall, ToolResult

logger = logging.getLogger(__name__)


def _load_mitre_kb() -> List[Dict]:
    """Load the MITRE ATT&CK knowledge base from YAML."""
    config_dir = os.environ.get("CONFIG_DIR", os.path.join(os.path.dirname(__file__), "../../../config"))
    kb_path = os.path.join(config_dir, "mitre_mapping.yaml")

    try:
        with open(kb_path, "r") as f:
            data = yaml.safe_load(f)
        return data.get("techniques", [])
    except FileNotFoundError:
        logger.error("MITRE mapping file not found at %s", kb_path)
        return []
    except Exception as e:
        logger.error("Error loading MITRE knowledge base: %s", e)
        return []


# Cache the knowledge base in memory
_MITRE_KB: Optional[List[Dict]] = None


def get_mitre_kb() -> List[Dict]:
    global _MITRE_KB
    if _MITRE_KB is None:
        _MITRE_KB = _load_mitre_kb()
    return _MITRE_KB


def lookup_mitre(
    event_types: List[str],
    context: Dict[str, Any],
    agent: AgentName = AgentName.INVESTIGATOR,
    incident_id: Optional[str] = None,
) -> tuple[ToolCall, ToolResult]:
    """
    Look up applicable MITRE ATT&CK techniques for the given event types.
    
    Args:
        event_types: List of observed cloud event types
        context: Additional context (user, IPs, parameters)
        agent: The calling agent
        incident_id: Associated incident ID
    
    Returns:
        (ToolCall, ToolResult) where ToolResult.data is a list of MitreTechnique
    """
    call = ToolCall(
        tool_name="lookup_mitre",
        agent=agent,
        incident_id=incident_id,
        arguments={"event_types": event_types, "context_keys": list(context.keys())},
    )

    try:
        kb = get_mitre_kb()
        if not kb:
            return call, ToolResult(
                tool_id=call.tool_id,
                tool_name=call.tool_name,
                success=False,
                error="MITRE knowledge base is empty or could not be loaded",
            )

        matched_techniques: List[MitreTechnique] = []
        event_set = set(event_types)

        for technique in kb:
            relevant = set(technique.get("relevant_events", []))
            overlap = event_set.intersection(relevant)

            if not overlap:
                continue

            # Calculate evidence-based confidence
            coverage = len(overlap) / max(len(relevant), 1)
            base_confidence = technique.get("severity_weight", 0.5)

            # Apply context boosts
            confidence = min(base_confidence * (0.5 + coverage * 0.5), 1.0)

            # Context boost: impossible travel → boost T1078
            if technique["technique_id"] == "T1078" and context.get("impossible_travel"):
                confidence = min(confidence + 0.2, 1.0)

            # Context boost: admin policy attached → boost T1098
            if technique["technique_id"] == "T1098" and any(
                "AdministratorAccess" in str(context.get(k, ""))
                for k in context
            ):
                confidence = min(confidence + 0.15, 1.0)

            matched_techniques.append(MitreTechnique(
                technique_id=technique["technique_id"],
                technique_name=technique["technique_name"],
                tactic=technique["tactic"],
                description=technique.get("description", "").strip(),
                confidence=round(confidence, 3),
                evidence=list(overlap),
            ))

        # Sort by confidence descending
        matched_techniques.sort(key=lambda t: t.confidence, reverse=True)

        return call, ToolResult(
            tool_id=call.tool_id,
            tool_name=call.tool_name,
            success=True,
            data=[t.model_dump() for t in matched_techniques],
        )

    except Exception as e:
        logger.exception("Error in MITRE lookup: %s", e)
        return call, ToolResult(
            tool_id=call.tool_id,
            tool_name=call.tool_name,
            success=False,
            error=str(e),
        )


def get_technique_by_id(technique_id: str) -> Optional[Dict]:
    """Direct lookup of a technique by ID."""
    kb = get_mitre_kb()
    return next((t for t in kb if t["technique_id"] == technique_id), None)
