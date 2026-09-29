"""MITRE ATT&CK: deterministic candidates before the LLM, deterministic status after it.

Candidates: techniques from config/mitre_mapping.yaml whose relevant_events occur in the
incident's events (details fetched with the read-only get_mitre_technique tool).
Status: a model-proposed technique is 'confirmed' only when its cited evidence includes a
relevant event AND its confidence meets config; otherwise it stays a 'candidate'.
Unknown technique IDs are rejected by validation before this point.
"""

from pathlib import Path
from typing import Any

from app.agents.investigator.config import InvestigatorConfig
from app.agents.investigator.evidence import EvidenceCatalog
from app.domain.investigation import MitreAssessment, MitreProposal, MitreStatus
from app.knowledge.mitre import load_techniques, techniques_for_event


def candidate_techniques(catalog: EvidenceCatalog, config_dir: Path,
                         lookup: Any = None, limit: int = 10) -> list[dict[str, Any]]:
    """[{technique_id, name, tactic, matched_evidence_ids, relevant_events}] ordered by support."""
    matched: dict[str, list[str]] = {}
    for event in catalog.events:
        for technique_id in techniques_for_event(config_dir, event.event_type):
            matched.setdefault(technique_id, []).append(event.evidence_id)
    techniques = load_techniques(config_dir)
    candidates = []
    for technique_id, evidence_ids in matched.items():
        info = (lookup(technique_id) if lookup else None) or techniques[technique_id]
        candidates.append({"technique_id": technique_id, "name": info["name"], "tactic": info["tactic"],
                           "matched_evidence_ids": evidence_ids,
                           "relevant_events": techniques[technique_id]["relevant_events"]})
    candidates.sort(key=lambda c: (-len(c["matched_evidence_ids"]), -c["technique_id"].count("."),
                                   c["technique_id"]))
    return candidates[:limit]


def assess(proposals: list[MitreProposal], catalog: EvidenceCatalog, config_dir: Path,
           config: InvestigatorConfig) -> list[MitreAssessment]:
    techniques = load_techniques(config_dir)
    event_types = {e.evidence_id: e.event_type for e in catalog.events}
    rule = config.mitre_confirmation
    results = []
    for proposal in proposals:
        info = techniques[proposal.technique_id]
        relevant = [i for i in proposal.evidence_ids if event_types.get(i) in info["relevant_events"]]
        confident = proposal.confidence >= rule.min_confidence
        confirmed = confident and (bool(relevant) or not rule.require_relevant_event)
        if confirmed:
            note = (f"confirmed: cited {', '.join(relevant)} ({', '.join(event_types[i] for i in relevant)}) "
                    f"match the technique's relevant events; confidence >= {rule.min_confidence}")
        elif not relevant:
            note = ("candidate: no cited event is one of the technique's relevant events "
                    f"({', '.join(info['relevant_events'][:5])})")
        else:
            note = f"candidate: confidence {proposal.confidence} below {rule.min_confidence}"
        results.append(MitreAssessment(
            technique_id=proposal.technique_id, technique_name=info["name"], tactic=info["tactic"],
            confidence=proposal.confidence, evidence_ids=proposal.evidence_ids, rationale=proposal.rationale,
            status=MitreStatus.CONFIRMED if confirmed else MitreStatus.CANDIDATE, validation_note=note))
    return results
