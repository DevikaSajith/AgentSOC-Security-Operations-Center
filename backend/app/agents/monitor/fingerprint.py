"""Stable event fingerprints for deduplication.

The fingerprint identifies *what happened*, not *which copy we received*:
  - it hashes a canonical JSON (sorted keys, fixed separators), so key order is irrelevant;
  - per-copy identifiers (our event_id, CloudTrail eventID, finding Id) are excluded, so a
    re-delivered copy with a new ID is still recognised;
  - the timestamp is included (normalised to UTC), so the same action repeated at a
    different time is NOT a duplicate.
"""

import hashlib
import json
from datetime import timezone
from typing import Any

from app.domain.events import SecurityEvent

# Keys that identify a delivery/copy rather than the activity itself (any nesting level).
VOLATILE_KEYS = frozenset({"eventID", "event_id", "id", "Id", "requestID", "sharedEventID"})


def _strip_volatile(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_volatile(v) for k, v in value.items() if k not in VOLATILE_KEYS}
    if isinstance(value, list):
        return [_strip_volatile(v) for v in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      default=str)


def fingerprint(event: SecurityEvent) -> str:
    """sha256 hex digest of the event's identity-defining fields."""
    identity = {
        "source": event.source.value,
        "account_id": event.account_id,
        "region": event.region,
        "event_type": event.event_type,
        "resource_id": event.resource_id,
        "principal_id": event.principal_id,
        "source_ip": event.source_ip,
        "timestamp": event.timestamp.astimezone(timezone.utc).isoformat(),
        "raw_event": _strip_volatile(event.raw_event),
    }
    return hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
