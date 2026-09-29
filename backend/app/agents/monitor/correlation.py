"""Stage 5: conservative, deterministic correlation of events into groups.

Two events are linked only when ALL of these hold:
  - same principal (never across identities; unknown principals only link to each other
    through a shared specific resource),
  - same source IP  OR  same specific resource (never the '*' wildcard),
  - at most `window_seconds` apart (chained: each event must be within the window of the
    previous linked event, so long quiet gaps split groups).
Events close in time but without a shared principal+IP/resource stay separate.

Implementation: events are walked in time order keeping the last event seen per key, so
the cost is O(n log n) for the sort plus O(n) lookups - no all-pairs comparison.
"""

import hashlib
from datetime import datetime

from app.agents.monitor.models import UNKNOWN_PRINCIPAL, UNSPECIFIED_IP, NormalizedEvent


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _keys(item: NormalizedEvent) -> list[tuple[str, str, str]]:
    event = item.event
    principal = event.principal_id
    keys = []
    if principal != UNKNOWN_PRINCIPAL and event.source_ip != UNSPECIFIED_IP:
        keys.append(("ip", principal, event.source_ip))
    if event.resource_id and event.resource_id != "*":
        keys.append(("resource", principal, event.resource_id))
    return keys


def group_id(items: list[NormalizedEvent]) -> str:
    digest = hashlib.sha256("|".join(sorted(i.fingerprint for i in items)).encode()).hexdigest()
    return f"GRP-{digest[:10].upper()}"


def correlate(events: list[NormalizedEvent], window_seconds: int) -> list[list[NormalizedEvent]]:
    """Groups of correlated events; each group and the list are ordered by time."""
    ordered = sorted(events, key=lambda i: (i.event.timestamp, i.event.event_id))
    links = _UnionFind(len(ordered))
    last_seen: dict[tuple[str, str, str], tuple[int, datetime]] = {}
    for index, item in enumerate(ordered):
        for key in _keys(item):
            previous = last_seen.get(key)
            if previous and (item.event.timestamp - previous[1]).total_seconds() <= window_seconds:
                links.union(previous[0], index)
            last_seen[key] = (index, item.event.timestamp)
    groups: dict[int, list[NormalizedEvent]] = {}
    for index, item in enumerate(ordered):
        groups.setdefault(links.find(index), []).append(item)
    return list(groups.values())  # roots are ascending indexes -> groups in time order
