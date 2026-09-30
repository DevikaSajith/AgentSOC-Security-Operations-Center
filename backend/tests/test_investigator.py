"""Investigator Agent tests. The LLM is always the deterministic MockLLMProvider."""

import json
import re
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.agents.investigator.agent import InvestigationRunRequest, InvestigatorAgent
from app.agents.investigator.config import load_investigator_config
from app.agents.investigator.context import InvestigationContextBuilder
from app.agents.investigator.entities import build_entities
from app.agents.investigator.evidence import EvidenceCollector
from app.agents.investigator.mitre import assess, candidate_techniques
from app.agents.investigator.prompts import SYSTEM_PROMPT
from app.agents.investigator.timeline import build_timeline
from app.agents.investigator.validation import InvestigationValidationError, validate_decision
from app.agents.monitor.agent import MonitorAgent
from app.agents.monitor.models import MonitorRunRequest
from app.agents.triage.agent import TriageAgent, TriageRunRequest
from app.agents.triage.config import load_triage_config
from app.config import Settings
from app.database.connection import Database
from app.domain.enums import AgentName, AgentRunStatus, IncidentStatus, Severity, TriageMethod
from app.domain.incident import AuditEntry, Evidence, IncidentState
from app.domain.investigation import (
    Certainty,
    InvestigationDecision,
    InvestigationNextStep,
    MitreProposal,
    MitreStatus,
)
from app.llm.mock import MockLLMProvider
from app.main import create_app
from app.services.event_service import EventService
from app.services.incident_service import IncidentService
from app.simulator.attacks import AttackSimulator
from app.simulator.cloud import CloudSimulator
from app.tools.base import ToolContext, ToolKind, ToolRequest
from app.tools.executor import ToolExecutor
from app.tools.registry import ACTION_TOOL_NAMES, build_default_registry
from tests.monitor_fixtures import config as monitor_config
from tests.test_triage import answer as triage_answer

CONFIG_DIR = Settings().config_dir
CONFIG = load_investigator_config(CONFIG_DIR)
TRIAGE_CONFIG = load_triage_config(CONFIG_DIR)


# ============================================================================ builders
def decision(**overrides) -> dict:
    """A valid model answer for the IAM scenario (EV1 Login, EV2 CreateAccessKey,
    EV3 AttachAdminPolicy, EV4 GetSecretValue; PR1 alice's IAM state)."""
    base = {
        "summary": "alice logged in from an untrusted IP, created an access key, attached an "
                   "administrator policy to herself and read the prod/db-password secret.",
        "confidence": 0.85,
        "timeline_notes": [
            {"evidence_id": "EV1", "significance": "Login from an unusual source IP"},
            {"evidence_id": "EV3", "significance": "Administrative policy attached to alice"}],
        "attack_sequence": [
            {"stage": "initial_access", "description": "Login from untrusted IP",
             "evidence_ids": ["EV1"], "certainty": "confirmed"},
            {"stage": "persistence", "description": "New access key created",
             "evidence_ids": ["EV2"], "certainty": "confirmed"},
            {"stage": "privilege_escalation", "description": "Admin policy attached",
             "evidence_ids": ["EV3", "PR1"], "certainty": "confirmed"},
            {"stage": "impact", "description": "Possible misuse of the secret",
             "evidence_ids": [], "certainty": "unsupported"}],
        "findings": [
            {"type": "privilege_escalation", "statement": "alice attached AdministratorAccess to her own user.",
             "evidence_ids": ["EV3", "PR1"], "confidence": 0.9, "certainty": "confirmed"},
            {"type": "credential_access", "statement": "alice read the production database password.",
             "evidence_ids": ["EV4"], "confidence": 0.7, "certainty": "suspected"}],
        "mitre_techniques": [
            {"technique_id": "T1098.003", "confidence": 0.9, "evidence_ids": ["EV3"],
             "rationale": "AttachAdminPolicy attaches an administrative role to the user."},
            {"technique_id": "T1555.006", "confidence": 0.7, "evidence_ids": ["EV4"],
             "rationale": "GetSecretValue reads a secret from the secrets manager."}],
        "root_cause_hypothesis": "Hypothesis: alice's credentials were misused from the untrusted IP.",
        "unknowns": ["How the credentials were obtained is not shown by the evidence."],
        "alternative_hypotheses": ["alice may have performed these actions from a new location."],
        "recommended_next_step": "compliance_review",
    }
    return {**base, **overrides}


def answer(**overrides) -> str:
    return json.dumps(decision(**overrides))


# ============================================================================ fixtures
@pytest.fixture()
def audit_entries() -> list[AuditEntry]:
    return []


@pytest.fixture()
def tools(cloud: CloudSimulator, database: Database, audit_entries) -> ToolExecutor:
    return ToolExecutor(ToolContext(cloud=cloud, database=database, registry=build_default_registry(),
                                    config_dir=CONFIG_DIR), audit_sink=audit_entries.append)


def make_incident(database: Database, cloud: CloudSimulator, tools: ToolExecutor,
                  scenario: str = "iam_privilege_escalation", triage: bool = True) -> str:
    events = AttackSimulator(cloud).run(scenario).events
    with database.session() as session:
        EventService(session).save_events(events)
    report = MonitorAgent(database, monitor_config(), tools, audit_sink=lambda e: None).run(
        MonitorRunRequest(event_ids=[e.event_id for e in events]))
    incident_id = report.incidents_created[0]
    if triage:
        TriageAgent(database, TRIAGE_CONFIG, MockLLMProvider([triage_answer()]), tools,
                    audit_sink=lambda e: None).run(TriageRunRequest(incident_id=incident_id))
    return incident_id


@pytest.fixture()
def incident_id(database, cloud, tools) -> str:
    return make_incident(database, cloud, tools)


def load(database: Database, incident_id: str) -> IncidentState:
    with database.session() as session:
        return IncidentService(session).get(incident_id)


def context_for(database, tools, incident_id: str):
    return InvestigationContextBuilder(CONFIG, tools, CONFIG_DIR).build(load(database, incident_id))


def make_agent(database, tools, audit_entries, provider) -> InvestigatorAgent:
    return InvestigatorAgent(database, CONFIG, provider, tools, audit_sink=audit_entries.append,
                             config_dir=CONFIG_DIR)


def investigate(agent: InvestigatorAgent, incident_id: str, **kwargs):
    return agent.run(InvestigationRunRequest(incident_id=incident_id, **kwargs))


# ============================================================================= evidence
def test_evidence_collection_builds_stable_catalog(database, tools, incident_id) -> None:
    ctx = context_for(database, tools, incident_id)
    items = ctx.catalog.items
    assert [i for i in items if i.startswith("EV")] == ["EV1", "EV2", "EV3", "EV4"]
    assert [items[i].description.split(" by ")[0] for i in ("EV1", "EV2", "EV3", "EV4")] == [
        "Login", "CreateAccessKey", "AttachAdminPolicy", "GetSecretValue"]
    assert items["PR1"].type == "iam" and items["PR1"].raw_reference["state"]["admin"] is True
    assert items["EV3"].observed and items["EV3"].confidence == 1.0
    assert items["MF1"].observed is False and items["TR1"].observed is False  # opinions, not facts
    assert items["EV1"].source == "CloudTrail"
    assert any(i.type == "resource" and "prod/db-password" in i.entity for i in items.values())


def test_evidence_is_incident_scoped(database, cloud, tools) -> None:
    first = make_incident(database, cloud, tools, "iam_privilege_escalation")
    second = make_incident(database, cloud, tools, "ec2_compromise")  # other principal (bob)
    ctx = context_for(database, tools, first)
    incident = load(database, first)
    assert set(ctx.catalog.event_ids) == set(incident.related_event_ids)
    text = ctx.to_json()
    assert second not in text and "ec2-001" not in text and "bob" not in text
    assert {e.principal for e in ctx.catalog.events} == {"alice"}


def test_only_incident_events_are_read_even_if_principal_has_others(database, cloud, tools) -> None:
    incident_id = make_incident(database, cloud, tools)
    extra = AttackSimulator(cloud).generator.create_event("ListUsers", user="alice", source_ip="203.0.113.10")
    with database.session() as session:
        EventService(session).save_event(extra)  # same principal, NOT part of the incident
    ctx = context_for(database, tools, incident_id)
    assert extra.event_id not in ctx.catalog.event_ids and len(ctx.catalog.events) == 4


def test_context_is_bounded(database, tools, incident_id) -> None:
    incident = load(database, incident_id)
    small = CONFIG.model_copy(update={"context": CONFIG.context.model_copy(update={
        "max_events": 2, "max_context_chars": 2500})})
    ctx = InvestigationContextBuilder(small, tools, CONFIG_DIR).build(incident)
    assert len(ctx.catalog.events) == 2
    assert [e.evidence_id for e in ctx.catalog.events] == ["EV1", "EV2"]
    assert any("Only the latest 2 of 4 events" in limit for limit in ctx.catalog.limitations)
    full = InvestigationContextBuilder(CONFIG, tools, CONFIG_DIR).build(incident)
    assert len(ctx.to_json()) < len(full.to_json())  # trimmed
    assert any("truncated" in limit for limit in ctx.catalog.limitations)


def test_context_has_no_credentials_or_ground_truth(database, tools, incident_id) -> None:
    text = context_for(database, tools, incident_id).to_json()
    assert not re.search(r"AKIA[A-Z0-9]{8,}", text) and "key_id" not in text
    assert not re.search(r'"[^"]*(password|secret|token|credential)[^"]*"\s*:', text, re.I)
    assert "scenario_id" not in text and "state_change" not in text
    assert str(CONFIG_DIR) not in text and "agentsoc.db" not in text


def test_context_contains_derived_analysis_not_just_the_incident(database, tools, incident_id) -> None:
    payload = context_for(database, tools, incident_id).payload
    assert {"evidence", "timeline", "entities", "relationships", "mitre_candidates",
            "stage_hints_by_event_type", "known_limitations", "allowed",
            "rules_your_answer_must_follow"} <= set(payload)
    assert payload["allowed"]["timeline_evidence_ids"] == ["EV1", "EV2", "EV3", "EV4"]
    assert "T1098.003" in payload["allowed"]["mitre_technique_ids"]
    assert payload["triage_summary_for_context_only"]["ref"] == "TR1"


def test_limitations_are_stated_not_hidden(database, tools, incident_id) -> None:
    limits = " ".join(context_for(database, tools, incident_id).catalog.limitations)
    assert "GuardDuty or Security Hub" in limits          # nothing fabricated
    assert "No network flow" in limits and "redacted" in limits


# ============================================================================== timeline
def test_timeline_is_chronological_and_traceable(database, tools, incident_id) -> None:
    ctx = context_for(database, tools, incident_id)
    times = [t.timestamp for t in ctx.timeline]
    assert times == sorted(times) and [t.evidence_id for t in ctx.timeline] == ["EV1", "EV2", "EV3", "EV4"]
    assert all(t.evidence_id in ctx.catalog.items for t in ctx.timeline)
    assert ctx.timeline[0].seconds_since_previous is None
    assert all(g > 0 for g in (t.seconds_since_previous for t in ctx.timeline[1:]))
    assert {"same_principal", "same_source_ip", "same_account"} <= set(ctx.timeline[1].shared_with_previous)
    assert "same_resource" in ctx.timeline[1].shared_with_previous  # Login and CreateAccessKey: IAMUser/alice


def test_timeline_handles_missing_timestamps_and_duplicates(database, tools, incident_id) -> None:
    incident = load(database, incident_id)
    dup = incident.evidence[0].model_copy(update={"evidence_id": "EVD-DUP"})  # same event twice
    events = [e for e in incident.evidence if e.kind == "event"]
    broken = events[1].model_copy(update={"data": {**events[1].data, "timestamp": "not a time"}})
    patched = incident.model_copy(update={"evidence": [dup, broken] + [e for e in incident.evidence
                                                                       if e not in (events[1],)]})
    collector = EvidenceCollector(None, 40, 8, 240)  # no tools: Monitor summaries only
    catalog = collector.collect(patched)
    assert len(catalog.events) == 4  # 5 records, 1 exact duplicate collapsed
    assert catalog.events[-1].timestamp is None      # undated events sort last
    text = " ".join(catalog.limitations)
    assert "duplicate" in text and "no timestamp" in text
    timeline = build_timeline(catalog)
    assert timeline[-1].seconds_since_previous is None and timeline[-1].timestamp is None


# =============================================================================== entities
def test_entity_extraction_and_relationships(database, tools, incident_id) -> None:
    ctx = context_for(database, tools, incident_id)
    by_value = {e.value: e for e in ctx.entities}
    assert by_value["alice"].type == "principal"
    assert by_value["Secret/prod/db-password"].type == "secret"
    ip = next(e for e in ctx.entities if e.type == "source_ip")
    assert ip.attributes["trusted"] is False and set(ip.evidence_ids) == {"EV1", "EV2", "EV3", "EV4"}
    assert {"account", "region"} <= {e.type for e in ctx.entities}
    names = {e.entity_id: e.value for e in ctx.entities}
    triples = {(names[r.source], r.relation, names[r.target]) for r in ctx.relationships}
    assert ("alice", "authenticated_from", ip.value) in triples
    assert ("alice", "acted_on", "Secret/prod/db-password") in triples
    assert (ip.value, "originated_activity_on", "Secret/prod/db-password") in triples
    assert any(rel == "created" and src == "alice" for src, rel, _ in triples)
    assert all(r.certainty == Certainty.CONFIRMED and r.evidence_ids for r in ctx.relationships)


def test_uncertain_relationship_is_explicit(database, tools) -> None:
    from tests.monitor_fixtures import ALICE_IP, event as build_event
    cloud = CloudSimulator()
    home, away = build_event("Login", ip=ALICE_IP, at=0), build_event("Login", at=30)
    away2 = build_event("AttachAdminPolicy", at=60)
    with database.session() as session:
        EventService(session).save_events([home, away, away2])
    report = MonitorAgent(database, monitor_config(), tools, audit_sink=lambda e: None).run(
        MonitorRunRequest(event_ids=[home.event_id, away.event_id, away2.event_id]))
    ctx = context_for(database, tools, report.incidents_created[0])
    same_actor = [r for r in ctx.relationships if r.relation == "same_actor_as"]
    assert same_actor and all(r.certainty == Certainty.POSSIBLE for r in same_actor)


# =================================================================================== MITRE
def test_mitre_candidates_come_from_project_mapping(database, tools, incident_id) -> None:
    ctx = context_for(database, tools, incident_id)
    ids = {c["technique_id"] for c in ctx.mitre_candidates}
    assert {"T1078.004", "T1098.001", "T1098.003", "T1555.006"} <= ids
    from app.knowledge.mitre import load_techniques
    assert ids <= set(load_techniques(CONFIG_DIR))
    ec2 = candidate_techniques(context_for(database, tools, make_incident(
        database, CloudSimulator(), tools, "ec2_compromise")).catalog, CONFIG_DIR)
    assert {"T1071.001", "T1041", "T1651"} <= {c["technique_id"] for c in ec2}


def test_valid_technique_accepted_and_invalid_rejected(database, tools, incident_id) -> None:
    ctx = context_for(database, tools, incident_id)
    validate_decision(answer(), ctx, CONFIG, CONFIG_DIR)
    bad = decision(mitre_techniques=[{"technique_id": "T9999", "confidence": 0.9, "evidence_ids": ["EV3"],
                                      "rationale": "This technique does not exist in the mapping."}])
    with pytest.raises(InvestigationValidationError) as info:
        validate_decision(json.dumps(bad), ctx, CONFIG, CONFIG_DIR)
    assert info.value.code == "invalid_mitre" and "T9999" in info.value.problems[0]


def test_mitre_requires_evidence(database, tools, incident_id) -> None:
    bad = decision(mitre_techniques=[{"technique_id": "T1098.003", "confidence": 0.9, "evidence_ids": [],
                                      "rationale": "Attached an admin policy to the user."}])
    with pytest.raises(InvestigationValidationError) as info:
        validate_decision(json.dumps(bad), context_for(database, tools, incident_id), CONFIG, CONFIG_DIR)
    assert info.value.code == "schema_invalid"  # min_length=1 on evidence_ids


def test_candidate_versus_confirmed_is_decided_by_the_backend(database, tools, incident_id) -> None:
    ctx = context_for(database, tools, incident_id)
    proposals = [
        MitreProposal(technique_id="T1098.003", confidence=0.9, evidence_ids=["EV3"],
                      rationale="AttachAdminPolicy is a relevant event for this technique."),
        MitreProposal(technique_id="T1098.003", confidence=0.4, evidence_ids=["EV3"],
                      rationale="Same evidence but low confidence in the mapping."),
        MitreProposal(technique_id="T1555.006", confidence=0.95, evidence_ids=["EV1"],
                      rationale="Cites a Login event, which is not a relevant event."),
        MitreProposal(technique_id="T1078.004", confidence=0.9, evidence_ids=["TR1"],
                      rationale="Cites only the triage opinion, not an event."),
    ]
    result = assess(proposals, ctx.catalog, CONFIG_DIR, CONFIG)
    assert [r.status for r in result] == [MitreStatus.CONFIRMED, MitreStatus.CANDIDATE,
                                          MitreStatus.CANDIDATE, MitreStatus.CANDIDATE]
    assert "confirmed: cited EV3" in result[0].validation_note
    assert "below 0.6" in result[1].validation_note
    assert "no cited event" in result[2].validation_note


# ==================================================================== LLM output validation
def rejected(database, tools, incident_id, text: str) -> InvestigationValidationError:
    with pytest.raises(InvestigationValidationError) as info:
        validate_decision(text, context_for(database, tools, incident_id), CONFIG, CONFIG_DIR)
    return info.value


def test_valid_response_is_accepted(database, tools, incident_id) -> None:
    parsed = validate_decision(answer(), context_for(database, tools, incident_id), CONFIG, CONFIG_DIR)
    assert isinstance(parsed, InvestigationDecision) and parsed.confidence == 0.85


def test_malformed_json_is_rejected(database, tools, incident_id) -> None:
    assert rejected(database, tools, incident_id, "I investigated it.").code == "invalid_json"
    assert rejected(database, tools, incident_id, '{"summary": ').code == "invalid_json"


def test_invalid_evidence_reference_is_rejected(database, tools, incident_id) -> None:
    findings = decision()["findings"]
    findings[0]["evidence_ids"] = ["EV3", "EV99"]
    err = rejected(database, tools, incident_id, answer(findings=findings))
    assert err.code == "invalid_evidence_ref" and "EV99" in err.problems[0]
    notes = [{"evidence_id": "PR1", "significance": "not a timeline event"}]
    assert rejected(database, tools, incident_id, answer(timeline_notes=notes)).code == "invalid_evidence_ref"


@pytest.mark.parametrize("overrides", [
    {"confidence": 1.7}, {"confidence": -0.2},
    {"recommended_next_step": "isolate_now"}, {"findings": []}, {"unknowns": []},
    {"root_cause_hypothesis": "short"},
])
def test_schema_violations_are_rejected(database, tools, incident_id, overrides) -> None:
    assert rejected(database, tools, incident_id, answer(**overrides)).code == "schema_invalid"


def test_unknown_fields_and_actions_are_rejected(database, tools, incident_id) -> None:
    data = decision()
    data["run_command"] = "disable_access_key alice"
    assert rejected(database, tools, incident_id, json.dumps(data)).code == "schema_invalid"


def test_semantic_rules(database, tools, incident_id) -> None:
    stages = decision()["attack_sequence"]
    stages[0]["evidence_ids"] = []  # 'confirmed' without evidence
    assert rejected(database, tools, incident_id, answer(attack_sequence=stages)).code == "semantic_invalid"
    stages = decision()["attack_sequence"]
    stages[3]["evidence_ids"] = ["EV1"]  # 'unsupported' must cite nothing
    assert rejected(database, tools, incident_id, answer(attack_sequence=stages)).code == "semantic_invalid"
    finding = decision()["findings"]
    finding[0]["certainty"] = "unsupported"
    assert rejected(database, tools, incident_id, answer(findings=finding)).code == "semantic_invalid"


def test_policy_rules(database, tools, incident_id) -> None:
    err = rejected(database, tools, incident_id, answer(summary="Something suspicious happened in the account."))
    assert err.code == "policy_violation" and "summary must name" in err.problems[0]
    err = rejected(database, tools, incident_id, answer(recommended_next_step="monitor"))
    assert err.code == "policy_violation" and "require recommended_next_step" in err.problems[0]
    err = rejected(database, tools, incident_id, answer(recommended_next_step="close"))
    assert err.code == "policy_violation"


def test_over_claims_are_downgraded_not_silently_kept(database, tools, incident_id, audit_entries) -> None:
    findings = decision()["findings"]
    findings[0].update({"evidence_ids": ["MF1"], "certainty": "confirmed", "confidence": 0.95})
    report = investigate(make_agent(database, tools, audit_entries, MockLLMProvider([answer(findings=findings)])),
                         incident_id)
    f = report.investigation.findings[0]
    assert report.status == AgentRunStatus.SUCCESS
    assert f.classification == Certainty.SUSPECTED and f.proposed_certainty == Certainty.CONFIRMED
    assert f.confidence == 0.79 and f.proposed_confidence == 0.95
    assert "observed evidence" in f.classification_note and "capped" in f.classification_note


# ===================================================================================== agent
def test_successful_investigation(database, tools, audit_entries, incident_id) -> None:
    triage_before = load(database, incident_id).triage
    report = investigate(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    assert report.status == AgentRunStatus.SUCCESS and report.outcome == "investigated"
    assert report.method == TriageMethod.LLM and report.attempts == 1
    inv = load(database, incident_id).investigation
    assert inv.provider == "mock" and inv.model == "mock-triage-1" and inv.status == "completed"
    assert inv.based_on_triage_run == triage_before.run_id
    assert [t.evidence_id for t in inv.timeline] == ["EV1", "EV2", "EV3", "EV4"]
    assert inv.timeline[0].significance == "Login from an unusual source IP"
    assert inv.timeline[1].significance is None  # not annotated -> stays empty, never invented
    assert [s.stage.value for s in inv.attack_sequence] == [
        "initial_access", "persistence", "privilege_escalation", "impact"]
    assert inv.attack_sequence[3].certainty == Certainty.UNSUPPORTED
    assert inv.root_cause_hypothesis.startswith("Hypothesis")
    assert inv.unknowns and inv.limitations and inv.alternative_hypotheses
    assert inv.recommended_next_step == InvestigationNextStep.COMPLIANCE_REVIEW
    assert {e.evidence_id for e in inv.evidence} >= {"EV1", "PR1", "MF1", "TR1"}
    assert inv.entities and inv.relationships
    mitre = {m.technique_id: m for m in inv.mitre_techniques}
    assert mitre["T1098.003"].status == MitreStatus.CONFIRMED and mitre["T1098.003"].technique_name


def test_incident_state_is_updated_and_triage_preserved(database, tools, audit_entries, incident_id) -> None:
    before = load(database, incident_id)
    investigate(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    after = load(database, incident_id)
    assert after.final_status == IncidentStatus.INVESTIGATED
    assert after.current_agent == AgentName.INVESTIGATOR
    assert after.triage == before.triage                       # historical triage untouched
    assert (after.severity, after.priority, after.category, after.confidence) == (
        before.severity, before.priority, before.category, before.confidence)
    assert [m.technique_id for m in after.mitre_techniques] == ["T1098.003", "T1555.006"]  # confirmed only
    assert [d.actor for d in after.agent_decisions] == [AgentName.MONITOR, AgentName.TRIAGE,
                                                        AgentName.INVESTIGATOR]
    assert after.remediation_plan is None and after.compliance is None  # later stages untouched


def test_investigation_adds_value_beyond_triage(database, tools, audit_entries, incident_id) -> None:
    investigate(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    incident = load(database, incident_id)
    inv, triage = incident.investigation, incident.triage
    assert inv.summary != triage.interpretation.summary
    assert len(inv.timeline) == 4 and inv.entities and inv.mitre_techniques and inv.findings
    assert triage.interpretation.classification not in inv.summary  # analysis, not a copy of triage


def test_untriaged_incident_is_gated(database, cloud, tools, audit_entries) -> None:
    incident_id = make_incident(database, cloud, tools, triage=False)
    provider = MockLLMProvider([answer()])
    report = investigate(make_agent(database, tools, audit_entries, provider), incident_id)
    assert report.status == AgentRunStatus.SKIPPED and report.outcome == "triage_required"
    assert provider.calls == [] and load(database, incident_id).investigation is None
    assert load(database, incident_id).triage is None  # Triage was NOT run implicitly
    forced = investigate(make_agent(database, tools, audit_entries, provider), incident_id, allow_untriaged=True)
    assert forced.status == AgentRunStatus.SUCCESS and load(database, incident_id).triage is None


def test_llm_unavailable_leaves_incident_unchanged(database, tools, audit_entries, incident_id) -> None:
    before = load(database, incident_id)
    report = investigate(make_agent(database, tools, audit_entries, MockLLMProvider(available=False)), incident_id)
    assert report.status == AgentRunStatus.FAILED and report.outcome == "llm_unavailable"
    assert report.investigation is None and load(database, incident_id) == before
    no_llm = investigate(make_agent(database, tools, audit_entries, None), incident_id)
    assert no_llm.outcome == "llm_not_configured"


def test_repair_succeeds(database, tools, audit_entries, incident_id) -> None:
    mock = MockLLMProvider(["<think>hidden</think> not json", answer()])
    report = investigate(make_agent(database, tools, audit_entries, mock), incident_id)
    assert report.status == AgentRunStatus.SUCCESS and report.attempts == 2
    assert report.validation_errors[0].startswith("invalid_json")
    assert "rejected by validation" in mock.calls[1]["user"] and "allowed" in mock.calls[1]["user"]


def test_repair_fails_without_changing_incident(database, tools, audit_entries, incident_id) -> None:
    before = load(database, incident_id)
    bad = decision()
    bad["findings"][0]["evidence_ids"] = ["EV404"]
    mock = MockLLMProvider([json.dumps(bad)])
    report = investigate(make_agent(database, tools, audit_entries, mock), incident_id)
    assert report.status == AgentRunStatus.FAILED and report.outcome == "invalid_llm_output"
    assert report.attempts == 1 + CONFIG.policy.max_repair_attempts == len(mock.calls)  # no endless retry
    assert load(database, incident_id) == before
    failed = [e for e in audit_entries if e.action == "investigator.failed"]
    assert failed and failed[0].result == "invalid_llm_output"


def test_rule_based_fallback_is_explicit_and_labelled(database, tools, audit_entries, incident_id) -> None:
    down = MockLLMProvider(available=False)
    report = investigate(make_agent(database, tools, audit_entries, down), incident_id,
                         allow_rule_based_fallback=True)
    assert report.status == AgentRunStatus.SUCCESS and report.outcome == "investigated_rule_based_fallback"
    inv = load(database, incident_id).investigation
    assert inv.method == TriageMethod.RULE_BASED_FALLBACK and inv.provider == "rule_based"
    assert "Rule-based fallback" in inv.summary and inv.confidence == CONFIG.fallback.confidence
    assert all(f.classification != Certainty.CONFIRMED for f in inv.findings)  # never claims confirmed
    assert report.validation_errors[0].startswith("llm_unavailable")


# ==================================================================================== security
def test_investigator_has_only_read_permissions() -> None:
    registry = build_default_registry()
    permitted = set(registry.permissions_for(AgentName.INVESTIGATOR))
    assert permitted == {"get_incident", "get_resource", "get_iam_entity", "get_cloudtrail_events",
                         "get_security_findings", "get_network_events", "get_asset_context",
                         "get_mitre_technique"}
    assert not permitted & ACTION_TOOL_NAMES
    assert all(registry.get(n).kind == ToolKind.READ for n in permitted)


def test_action_tools_denied_even_with_kill_switch_enabled(cloud, database) -> None:
    executor = ToolExecutor(ToolContext(cloud=cloud, database=database,
                                        registry=build_default_registry(agent_actions_enabled=True),
                                        config_dir=CONFIG_DIR))
    for tool, args in [("disable_access_key", {"username": "alice"}),
                       ("remove_admin_privileges", {"username": "alice"}),
                       ("isolate_instance", {"instance_id": "ec2-001"}),
                       ("make_bucket_private", {"bucket_name": "public-assets"})]:
        result = executor.execute(ToolRequest(tool_name=tool, arguments=args,
                                              requested_by=AgentName.INVESTIGATOR))
        assert result.error_code == "permission_denied"
    assert cloud.get_user("alice").access_key_active and cloud.get_bucket("public-assets").public_access


def test_model_cannot_smuggle_tool_calls(database, tools, audit_entries, incident_id, cloud) -> None:
    before = cloud.get_cloud_state()
    evil = decision()
    evil["actions"] = [{"tool": "disable_access_key", "username": "alice"}]
    mock = MockLLMProvider([json.dumps(evil)])
    report = investigate(make_agent(database, tools, audit_entries, mock), incident_id)
    assert report.outcome == "invalid_llm_output" and cloud.get_cloud_state() == before


def test_no_cloud_mutation_on_success(database, tools, audit_entries, incident_id, cloud) -> None:
    before = cloud.get_cloud_state()
    investigate(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    assert cloud.get_cloud_state() == before


def test_audit_contains_no_secrets_prompts_or_raw_output(database, tools, audit_entries, incident_id) -> None:
    mock = MockLLMProvider(["<think>private chain of thought</think>{", answer()])
    investigate(make_agent(database, tools, audit_entries, mock), incident_id)
    dumped = json.dumps([e.model_dump(mode="json") for e in audit_entries], default=str)
    assert "chain of thought" not in dumped and SYSTEM_PROMPT[:60] not in dumped
    assert "Context (JSON)" not in dumped and not re.search(r"AKIA[A-Z0-9]{8,}", dumped)


def test_audit_records_execution_details(database, tools, audit_entries, incident_id) -> None:
    investigate(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    actions = [e.action for e in audit_entries if e.actor == AgentName.INVESTIGATOR]
    assert actions == ["investigator.run", "investigator.completed"]
    done = next(e for e in audit_entries if e.action == "investigator.completed")
    assert done.incident_id == incident_id and done.details["provider"] == "mock"
    assert sorted(done.details["input_event_ids"]) == sorted(load(database, incident_id).related_event_ids)
    assert done.details["attempts"] == 1 and "T1098.003:confirmed" in done.details["decision"]["mitre"]


# ================================================================================ idempotency
def test_running_twice_is_safe_and_history_is_kept(database, tools, audit_entries, incident_id) -> None:
    agent = make_agent(database, tools, audit_entries, MockLLMProvider([answer(), answer(confidence=0.6)]))
    first, second = investigate(agent, incident_id), investigate(agent, incident_id)
    incident = load(database, incident_id)
    assert incident.investigation.run_id == second.run_id != first.run_id
    assert incident.investigation.confidence == 0.6
    assert len(incident.investigation.findings) == 2                       # replaced, not appended
    assert [d.actor for d in incident.agent_decisions].count(AgentName.INVESTIGATOR) == 1
    from app.services.agent_runs import AgentRunService
    with database.session() as session:
        stats = AgentRunService(session).stats(AgentName.INVESTIGATOR.value)
    assert stats["runs"] == 2 and stats["successful_runs"] == 2 and stats["last_incident_id"] == incident_id
    completed = [e for e in audit_entries if e.action == "investigator.completed"]
    assert {e.details["run_id"] for e in completed} == {first.run_id, second.run_id}


# ======================================================================================= API
@pytest.fixture()
def api(cloud: CloudSimulator, database: Database):
    def build(provider) -> TestClient:
        return TestClient(create_app(cloud=cloud, database=database, settings=Settings(), llm_provider=provider))
    return build


def scripted() -> MockLLMProvider:
    return MockLLMProvider.routed({"Triage Agent": [triage_answer()], "Investigator Agent": [answer()]})


def new_incident(client: TestClient, triage: bool = True) -> str:
    incident_id = client.post("/api/simulation/run",
                              json={"scenario": "iam_privilege_escalation", "run_monitor": True}).json()["incident_id"]
    if triage:
        assert client.post("/api/agents/triage/run", json={"incident_id": incident_id}).json()["status"] == "success"
    return incident_id


def test_investigator_endpoint_full_flow(api) -> None:
    with api(scripted()) as client:
        incident_id = new_incident(client)
        response = client.post("/api/agents/investigator/run", json={"incident_id": incident_id})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "success" and body["outcome"] == "investigated"
        assert body["agent_result"]["agent_name"] == "Investigator Agent"
        detail = client.get(f"/api/incidents/{incident_id}").json()
        assert detail["final_status"] == "investigated" and detail["current_agent"] == "Investigator Agent"
        inv = detail["investigation"]
        for key in ("timeline", "entities", "relationships", "attack_sequence", "findings",
                    "mitre_techniques", "root_cause_hypothesis", "unknowns", "alternative_hypotheses",
                    "recommended_next_step", "method", "provider", "model", "confidence", "summary"):
            assert key in inv
        assert detail["triage"]["interpretation"]["classification"]  # triage preserved
        agents = client.get("/api/agents").json()
        investigator = agents[2]
        assert investigator["implemented"] and investigator["stats"]["runs"] == 1
        assert investigator["stats"]["successful_runs"] == 1 and investigator["llm"]["provider"] == "mock"
        assert agents[3]["implemented"] is True and agents[3]["stats"]["runs"] == 0  # Compliance: not run
        assert agents[4]["implemented"] is True and agents[4]["stats"]["runs"] == 0
        actions = [e["action"] for e in client.get("/api/audit").json()]
        assert {"investigator.run", "investigator.completed"} <= set(actions)


@pytest.mark.parametrize("payload, status", [
    ({"incident_id": "INC-X", "unexpected": 1}, 422), ({}, 422),
    ({"incident_id": "../etc/passwd"}, 422), ({"incident_id": "INC-NOPE"}, 404)])
def test_investigator_endpoint_rejects_bad_requests(api, payload, status) -> None:
    with api(scripted()) as client:
        assert client.post("/api/agents/investigator/run", json=payload).status_code == status


def test_investigator_endpoint_untriaged(api) -> None:
    with api(scripted()) as client:
        incident_id = new_incident(client, triage=False)
        body = client.post("/api/agents/investigator/run", json={"incident_id": incident_id}).json()
        assert body["status"] == "skipped" and body["outcome"] == "triage_required"
        assert client.get(f"/api/incidents/{incident_id}").json()["investigation"] is None


def test_investigator_endpoint_llm_unavailable(api) -> None:
    with api(MockLLMProvider(available=False)) as client:
        incident_id = new_incident(client, triage=False)
        body = client.post("/api/agents/investigator/run",
                           json={"incident_id": incident_id, "allow_untriaged": True}).json()
        assert body["status"] == "failed" and body["outcome"] == "llm_unavailable"
        assert client.get(f"/api/incidents/{incident_id}").json()["investigation"] is None
        assert client.get("/api/agents").json()[2]["stats"]["failed_runs"] == 1


def test_investigator_endpoint_response_validates(api) -> None:
    from app.agents.investigator.agent import InvestigationRunReport
    with api(scripted()) as client:
        body = client.post("/api/agents/investigator/run", json={"incident_id": new_incident(client)}).json()
    assert InvestigationRunReport.model_validate(body).investigation is not None


def test_investigator_endpoint_503_without_rules(cloud, database, tmp_path: Path) -> None:
    with TestClient(create_app(cloud=cloud, database=database, settings=Settings(config_dir=tmp_path),
                               llm_provider=scripted())) as client:
        assert client.post("/api/agents/investigator/run", json={"incident_id": "INC-1"}).status_code == 503


def test_monitor_and_triage_do_not_trigger_investigation(api) -> None:
    with api(scripted()) as client:
        incident_id = new_incident(client)
        assert client.get(f"/api/incidents/{incident_id}").json()["investigation"] is None
        assert client.get("/api/agents").json()[2]["stats"]["runs"] == 0
