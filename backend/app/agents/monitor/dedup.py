"""Stage 4: deterministic deduplication by fingerprint (see fingerprint.py)."""

from dataclasses import dataclass, field

from app.agents.monitor.models import DuplicateEvent, NormalizedEvent


@dataclass
class DedupResult:
    unique: list[NormalizedEvent] = field(default_factory=list)
    duplicates: list[DuplicateEvent] = field(default_factory=list)
    already_processed: list[str] = field(default_factory=list)


def deduplicate(events: list[NormalizedEvent], processed_event_ids: set[str],
                processed_fingerprints: dict[str, str]) -> DedupResult:
    """Split events into unique / duplicates / already processed.

    processed_event_ids:     event IDs the Monitor has processed in earlier runs
    processed_fingerprints:  fingerprint -> event_id of those earlier events
    Lookups are dict/set based: O(n) for the batch.
    """
    result = DedupResult()
    first_in_batch: dict[str, str] = {}
    for item in events:
        event_id, fp = item.event.event_id, item.fingerprint
        if event_id in processed_event_ids:
            result.already_processed.append(event_id)
        elif fp in first_in_batch:
            result.duplicates.append(DuplicateEvent(
                event_id=event_id, duplicate_of=first_in_batch[fp], kind="in_batch"))
        elif fp in processed_fingerprints:
            result.duplicates.append(DuplicateEvent(
                event_id=event_id, duplicate_of=processed_fingerprints[fp],
                kind="previously_processed"))
        else:
            first_in_batch[fp] = event_id
            result.unique.append(item)
    return result
