"""Static MITRE ATT&CK reference data, loaded from config/mitre_mapping.yaml.

This is a lookup table only. Deciding which technique applies to an incident is done by
the Investigator Agent (LLM proposal + deterministic validation).
"""

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

MITRE_FILE = "mitre_mapping.yaml"


def _entry(technique_id: str, name: str, tactic: str, description: str,
           relevant_events: list[str], indicators: list[str],
           parent: str | None = None) -> dict[str, Any]:
    entry = {"technique_id": technique_id, "name": name, "tactic": tactic,
             "description": description, "relevant_events": relevant_events,
             "indicators": indicators}
    if parent:
        entry["parent_technique_id"] = parent
    return entry


@lru_cache(maxsize=4)
def load_techniques(config_dir: Path) -> dict[str, dict[str, Any]]:
    """Index techniques and sub-techniques by ID. Empty if the file is missing."""
    path = config_dir / MITRE_FILE
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    index: dict[str, dict[str, Any]] = {}
    for item in data.get("techniques", []):
        base_id, base_name = item["technique_id"], item.get("technique_name", "")
        tactic = item.get("tactic", "")
        description = " ".join(str(item.get("description", "")).split())
        events = list(item.get("relevant_events", []))
        indicators = list(item.get("indicators", []))
        index[base_id] = _entry(base_id, base_name, tactic, description, events, indicators)
        subs = list(item.get("sub_techniques", []))
        if item.get("sub_technique"):  # older single form: inherits the parent's events
            subs.append({"id": item["sub_technique"], "name": item.get("sub_technique_name", ""),
                         "relevant_events": events})
        for sub in subs:
            name = f"{base_name}: {sub.get('name', '')}".rstrip(": ")
            index[sub["id"]] = _entry(sub["id"], name, tactic, description,
                                      list(sub.get("relevant_events", events)), indicators,
                                      parent=base_id)
    return index


def get_technique(config_dir: Path, technique_id: str) -> dict[str, Any] | None:
    """One technique by ID (e.g. 'T1098' or 'T1098.001'), or None."""
    return load_techniques(config_dir).get(technique_id)


def techniques_for_event(config_dir: Path, event_type: str) -> list[str]:
    """IDs of techniques whose relevant_events include this event type (most specific first)."""
    matches = [tid for tid, t in load_techniques(config_dir).items()
               if event_type in t["relevant_events"]]
    return sorted(matches, key=lambda tid: (-tid.count("."), tid))
