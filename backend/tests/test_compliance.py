"""Compliance Agent tests. The LLM is always the deterministic MockLLMProvider."""

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.agents.compliance.agent import ComplianceAgent, ComplianceRunRequest
from app.agents.compliance.config import (
    ComplianceConfigError,
    ComplianceMapping,
    load_compliance_settings,
)
from app.agents.compliance.context import ComplianceContextBuilder
from app.agents.compliance.prompts import SYSTEM_PROMPT
from app.agents.compliance.validation import ComplianceValidationError, finalize, validate_decision
from app.agents.investigator.agent import InvestigationRunRequest
from app.config import Settings
from app.database.connection import Database
from app.domain.compliance import (
    ComplianceDecision,
    ComplianceStatus,
    DataClassification,
    ReportingStatus,
)
from app.domain.enums import AgentName, AgentRunStatus, IncidentStatus, TriageMethod
from app.domain.incident import AuditEntry, IncidentState
from app.llm.mock import MockLLMProvider
from app.main import create_app
from app.services.agent_runs import AgentRunService
from app.services.incident_service import IncidentService
from app.simulator.cloud import CloudSimulator
from app.tools.base import ToolContext, ToolKind, ToolRequest
from app.tools.executor import ToolExecutor
from app.tools.registry import ACTION_TOOL_NAMES, build_default_registry
from tests.test_investigator import answer as investigation_answer
from tests.test_investigator import investigate, make_agent as make_investigator, make_incident
from tests.test_triage import answer as triage_answer

CONFIG_DIR = Settings().config_dir
SETTINGS = load_compliance_settings(CONFIG_DIR)


# ============================================================================ builders
def decision(**overrides) -> dict:
    """A valid model answer for the IAM scenario (EV1 Login, EV2 CreateAccessKey, EV3 AttachAdminPolicy,
    EV4 GetSecretValue, PR1 alice, AS1 IAMUser/alice, AS2 Secret/prod/db-password)."""
    base = {
        "summary": "The incident engages least-privilege and credential-management controls and touches a "
                   "restricted secret; asset ownership and framework applicability are unknown.",
        "confidence": 0.8,
        "control_assessments": [
            {"control_id": "least_privilege", "status": "violation", "evidence_ids": ["EV3", "PR1"],
             "confidence": 0.85, "rationale": "An administrative policy was attached from an untrusted IP."},
            {"control_id": "credential_management", "status": "potential_gap", "evidence_ids": ["EV2", "EV4"],
             "confidence": 0.7, "rationale": "A new access key was created and a secret was read."},
            {"control_id": "data_protection", "status": "potential_gap", "evidence_ids": ["EV4", "AS2"],
             "confidence": 0.6, "rationale": "A restricted secret was retrieved by the affected principal."},
            {"control_id": "incident_response", "status": "unknown", "evidence_ids": [],
             "confidence": 0.3, "rationale": "Response process evidence is not available."}],
        "framework_assessments": [
            {"framework": "NIST_CSF", "framework_control_id": "PR.AA-05", "control_id": "least_privilege",
             "status": "potential_violation", "evidence_ids": ["EV3"], "confidence": 0.8,
             "rationale": "Privileged access was granted outside a managed process."}],
        "control_gaps": [
            {"control_id": "credential_management", "description": "Access key creation is not restricted.",
             "evidence_ids": ["EV2"]}],
        "potential_violations": [
            {"control_id": "least_privilege", "rule_id": "VR-PRIV-001", "status": "violation",
             "statement": "Configured rule VR-PRIV-001 matches the policy attachment.", "evidence_ids": ["EV3", "PR1"]}],
        "reporting_considerations": [
            {"status": "configured_requirement", "rule_id": "RPT-INT-001",
             "note": "Internal escalation to the security team lead is configured.", "evidence_ids": ["EV3"]}],
        "recommendations": [
            {"type": "review_iam_privileges", "control_id": "least_privilege",
             "rationale": "Review who holds administrative rights.", "evidence_ids": ["EV3"]},
            {"type": "review_credential_rotation", "control_id": "credential_management",
             "rationale": "Review access key issuance and rotation.", "evidence_ids": ["EV2"]}],
        "unknowns": ["Asset owner is not available.", "Applicability of each framework is not known."],
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


def make_investigated(database, cloud, tools, audit_entries, scenario="iam_privilege_escalation") -> str:
    incident_id = make_incident(database, cloud, tools, scenario)
    report = investigate(make_investigator(database, tools, audit_entries,
                                           MockLLMProvider([investigation_answer()])), incident_id)
    assert report.status == AgentRunStatus.SUCCESS, report.validation_errors
    return incident_id


@pytest.fixture()
def incident_id(database, cloud, tools, audit_entries) -> str:
    return make_investigated(database, cloud, tools, audit_entries)


def load(database: Database, incident_id: str) -> IncidentState:
    with database.session() as session:
        return IncidentService(session).get(incident_id)


def build_context(database, tools, incident_id: str, settings=SETTINGS):
    return ComplianceContextBuilder(settings, tools).build(load(database, incident_id))


def make_agent(database, tools, audit_entries, provider, settings=SETTINGS) -> ComplianceAgent:
    return ComplianceAgent(database, settings, provider, tools, audit_sink=audit_entries.append)


def assess(agent: ComplianceAgent, incident_id: str, **kwargs):
    return agent.run(ComplianceRunRequest(incident_id=incident_id, **kwargs))


def rejected(database, tools, incident_id, text: str) -> ComplianceValidationError:
    with pytest.raises(ComplianceValidationError) as info:
        validate_decision(text, build_context(database, tools, incident_id), SETTINGS)
    return info.value


# ============================================================================= context
def test_context_is_built_from_the_investigated_incident(database, tools, incident_id) -> None:
    ctx = build_context(database, tools, incident_id)
    payload = ctx.payload
    assert {"incident", "triage_summary", "investigation_summary", "evidence", "assets", "candidate_controls",
            "matched_violation_rules", "matched_reporting_rules", "allowed",
            "rules_your_answer_must_follow"} <= set(payload)
    assert payload["investigation_summary"]["summary"]                    # investigation included
    assert payload["triage_summary"]["classification"]                    # triage included
    controls = {c["control_id"]: c for c in payload["candidate_controls"]}
    assert {"least_privilege", "credential_management", "data_protection", "access_control",
            "incident_response"} <= set(controls)
    assert "network_security" not in controls                            # nothing engages it
    assert controls["least_privilege"]["framework_mappings"]["ISO_27001"] == [
        {"id": "A.8.2", "title": "Privileged access rights"}]
    assert [m["rule_id"] for m in payload["matched_violation_rules"]] == ["VR-PRIV-001"]
    ids = {e["id"] for e in payload["evidence"]}
    assert {"EV1", "EV4", "PR1", "AS1", "AS2", "IF1", "MT1", "MF1", "TR1"} <= ids
    assert next(e for e in payload["evidence"] if e["id"] == "AS1")["observed"] is True
    assert next(e for e in payload["evidence"] if e["id"] == "IF1")["observed"] is False


def test_assets_use_configured_classification_only(database, tools, incident_id) -> None:
    analysis = build_context(database, tools, incident_id).analysis
    by_id = {a.identifier: a for a in analysis.assets}
    assert by_id["Secret/prod/db-password"].classification == DataClassification.RESTRICTED
    assert by_id["Secret/prod/db-password"].environment == "production"
    alice = by_id["IAMUser/alice"]
    assert alice.classification == DataClassification.UNKNOWN and alice.owner is None  # never guessed
    assert alice.state["admin"] is True                                    # real simulator state
    assert {d.identifier for d in analysis.data} == {"Secret/prod/db-password"}
    text = " ".join(analysis.standing_unknowns)
    assert "IAMUser/alice" in text and "owner" in text and "Jurisdiction" in text and "retention" in text


def test_unrelated_incidents_are_excluded(database, cloud, tools, audit_entries) -> None:
    first = make_investigated(database, cloud, tools, audit_entries, "iam_privilege_escalation")
    other = make_incident(database, cloud, tools, "ec2_compromise")             # bob / ec2-001
    investigate(make_investigator(database, tools, audit_entries, MockLLMProvider(available=False)), other,
                allow_rule_based_fallback=True)
    text = build_context(database, tools, first).to_json()
    assert "bob" not in text and "ec2-001" not in text and "network_security" not in text


def test_context_has_no_credentials(database, tools, incident_id) -> None:
    text = build_context(database, tools, incident_id).to_json()
    assert not re.search(r"AKIA[A-Z0-9]{8,}", text) and "key_id" not in text
    assert not re.search(r'"[^"]*(password|secret|token|credential)[^"]*"\s*:', text, re.I)
    assert str(CONFIG_DIR) not in text and "agentsoc.db" not in text and "scenario_id" not in text


def test_context_is_bounded(database, tools, incident_id) -> None:
    small = SETTINGS.model_copy(update={"config": SETTINGS.config.model_copy(update={
        "context": SETTINGS.config.context.model_copy(update={"max_context_chars": 3000})})})
    full, trimmed = build_context(database, tools, incident_id), build_context(database, tools, incident_id, small)
    assert len(trimmed.payload["evidence"]) < len(full.payload["evidence"])
    assert {e["id"] for e in trimmed.payload["evidence"]} == set(trimmed.payload["allowed"]["evidence_ids"])
    assert trimmed.payload["evidence"][0]["id"].startswith("AS")            # high-priority items kept first


# ============================================================================= evidence
def test_valid_evidence_is_accepted(database, tools, incident_id) -> None:
    parsed = validate_decision(answer(), build_context(database, tools, incident_id), SETTINGS)
    assert isinstance(parsed, ComplianceDecision) and parsed.confidence == 0.8


def test_invalid_evidence_is_rejected(database, tools, incident_id) -> None:
    controls = decision()["control_assessments"]
    controls[0]["evidence_ids"] = ["EV3", "EV99"]
    err = rejected(database, tools, incident_id, answer(control_assessments=controls))
    assert err.code == "invalid_evidence_ref" and "EV99" in err.problems[0]


def test_missing_evidence_is_handled(database, tools, incident_id) -> None:
    controls = decision()["control_assessments"]
    controls[1]["evidence_ids"] = []                                       # adverse status, no evidence
    assert rejected(database, tools, incident_id, answer(control_assessments=controls)).code == "semantic_invalid"
    controls[1]["status"] = "unknown"                                      # unknown may cite nothing
    validate_decision(answer(control_assessments=controls, control_gaps=[]),
                      build_context(database, tools, incident_id), SETTINGS)


def test_every_compliance_finding_requires_evidence(database, tools, incident_id) -> None:
    gap = decision()["control_gaps"]
    gap[0]["evidence_ids"] = []
    assert rejected(database, tools, incident_id, answer(control_gaps=gap)).code == "schema_invalid"
    violation = decision()["potential_violations"]
    violation[0]["evidence_ids"] = []
    assert rejected(database, tools, incident_id, answer(potential_violations=violation)).code == "schema_invalid"


def test_compliant_cannot_be_claimed_from_an_opinion(database, tools, incident_id) -> None:
    """Found with the real model: 'incident_response is compliant' citing only Triage's opinion."""
    controls = decision()["control_assessments"]
    controls[3].update({"status": "compliant", "evidence_ids": ["TR1"]})
    err = rejected(database, tools, incident_id, answer(control_assessments=controls))
    assert err.code == "policy_violation" and "compliance is never assumed" in err.problems[0]


def test_matched_reporting_rules_are_forced_to_configured_requirement(database, tools, audit_entries, incident_id) -> None:
    """Found with the real model: matched rules were attached with status requires_manual_assessment."""
    reporting = [{"status": "requires_manual_assessment", "rule_id": "RPT-INT-001",
                  "note": "Internal escalation is configured for this incident.", "evidence_ids": ["EV3"]}]
    assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer(reporting_considerations=reporting)])),
           incident_id)
    compliance = load(database, incident_id).compliance
    assert compliance.reporting_status == ReportingStatus.CONFIGURED_REQUIREMENT
    by_rule = {r.rule_id: r for r in compliance.reporting_considerations}
    assert by_rule["RPT-INT-001"].status == ReportingStatus.CONFIGURED_REQUIREMENT
    assert by_rule["RPT-INT-001"].requirement == "internal_escalation" and by_rule["RPT-INT-001"].source == "llm"
    assert "set by the backend" in by_rule["RPT-INT-001"].note


@pytest.mark.parametrize("rationale", [
    "Remove AdministratorAccess policy from alice's account to prevent escalation.",
    "Review the role. Disable the access key immediately.",
    "Rotate programmatic access keys and enforce rotation policies.",
])
def test_recommendations_must_not_be_remediation_steps(database, tools, incident_id, rationale) -> None:
    """Found with the real model: 'Remove AdministratorAccess policy ...' as a recommendation."""
    recs = decision()["recommendations"]
    recs[0]["rationale"] = rationale
    err = rejected(database, tools, incident_id, answer(recommendations=recs))
    assert err.code == "policy_violation" and "remediation step" in err.problems[0]


def test_review_style_recommendations_are_accepted(database, tools, incident_id) -> None:
    recs = decision()["recommendations"]
    recs[0]["rationale"] = "Review whether the administrative policy should remain attached to this user."
    validate_decision(answer(recommendations=recs), build_context(database, tools, incident_id), SETTINGS)


def test_adverse_status_needs_observed_evidence(database, tools, incident_id) -> None:
    controls = decision()["control_assessments"]
    controls[1]["evidence_ids"] = ["IF1", "TR1"]                           # opinions only
    err = rejected(database, tools, incident_id, answer(control_assessments=controls))
    assert err.code == "policy_violation" and "OBSERVED" in err.problems[0]


# ============================================================================== controls
def test_valid_control_mapping_is_resolved_from_configuration(database, tools, audit_entries, incident_id) -> None:
    assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    controls = {c.control_id: c for c in load(database, incident_id).compliance.controls}
    assert controls["least_privilege"].control_name == "Least Privilege / Privileged Access"
    assert controls["incident_response"].status == ComplianceStatus.UNKNOWN


def test_invalid_control_is_rejected(database, tools, incident_id) -> None:
    controls = decision()["control_assessments"]
    controls[0]["control_id"] = "firewall_hardening"
    err = rejected(database, tools, incident_id, answer(control_assessments=controls))
    assert err.code == "invalid_control" and "firewall_hardening" in err.problems[0]
    controls[0]["control_id"] = "network_security"                        # exists, but not engaged here
    assert rejected(database, tools, incident_id, answer(control_assessments=controls)).code == "invalid_control"


def test_control_gap_and_potential_violation_are_stored(database, tools, audit_entries, incident_id) -> None:
    assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    compliance = load(database, incident_id).compliance
    assert [g.control_id for g in compliance.control_gaps] == ["credential_management"]
    assert compliance.control_gaps[0].control_name == "Credential Management"
    assert [(v.control_id, v.rule_id) for v in compliance.potential_violations] == [("least_privilege", "VR-PRIV-001")]
    assert compliance.matched_violation_rules[0].rule_id == "VR-PRIV-001"


def test_gap_must_match_an_adverse_control_assessment(database, tools, incident_id) -> None:
    gaps = [{"control_id": "incident_response", "description": "Response process could not be assessed.",
             "evidence_ids": ["EV1"]}]                                     # control was 'unknown'
    assert rejected(database, tools, incident_id, answer(control_gaps=gaps)).code == "semantic_invalid"


def test_confirmed_violation_requires_a_configured_rule(database, tools, audit_entries, incident_id) -> None:
    controls = decision()["control_assessments"]
    controls[1]["status"] = "violation"                                    # credential_management: no rule
    violations = decision()["potential_violations"] + [
        {"control_id": "credential_management", "rule_id": None, "status": "violation",
         "statement": "The access key creation is a violation.", "evidence_ids": ["EV2"]}]
    assess(make_agent(database, tools, audit_entries,
                      MockLLMProvider([answer(control_assessments=controls, potential_violations=violations)])),
           incident_id)
    compliance = load(database, incident_id).compliance
    by_id = {c.control_id: c for c in compliance.controls}
    assert by_id["credential_management"].status == ComplianceStatus.POTENTIAL_VIOLATION
    assert by_id["credential_management"].proposed_status == ComplianceStatus.VIOLATION
    assert "matched configured violation rule" in by_id["credential_management"].note
    assert by_id["least_privilege"].status == ComplianceStatus.VIOLATION and by_id["least_privilege"].note is None
    downgraded = [v for v in compliance.potential_violations if v.control_id == "credential_management"][0]
    assert downgraded.status == ComplianceStatus.POTENTIAL_VIOLATION and downgraded.note


def test_violation_without_any_matching_rule_is_downgraded(database, cloud, tools, audit_entries) -> None:
    incident_id = make_investigated(database, cloud, tools, audit_entries, "credential_misuse")
    ctx = build_context(database, tools, incident_id)
    assert ctx.analysis.violation_matches == []
    decision_ = validate_decision(json.dumps({**decision(), "control_assessments": [
        {"control_id": "credential_management", "status": "violation", "evidence_ids": ["EV4"],
         "confidence": 0.9, "rationale": "Sensitive data was read from an untrusted IP."}],
        "control_gaps": [], "potential_violations": [], "framework_assessments": [],
        "recommendations": decision()["recommendations"][1:],
        "reporting_considerations": [{"status": "requires_manual_assessment", "rule_id": None,
                                      "note": "Manual assessment needed.", "evidence_ids": []}]}), ctx, SETTINGS)
    final = finalize(decision_, ctx, SETTINGS)
    assert final.controls[0].status == ComplianceStatus.POTENTIAL_VIOLATION
    assert final.overall_status == ComplianceStatus.POTENTIAL_VIOLATION      # derived, not claimed


def test_rule_attached_to_the_wrong_control_is_downgraded(database, tools, audit_entries, incident_id) -> None:
    """A real qwen3:4b run put VR-PRIV-001 on 'access_control'; a rule only counts for its own control."""
    controls = decision()["control_assessments"] + [
        {"control_id": "access_control", "status": "violation", "evidence_ids": ["EV1"], "confidence": 0.7,
         "rationale": "Login from an untrusted IP preceded the policy change."}]
    violations = [{"control_id": "access_control", "rule_id": "VR-PRIV-001", "status": "violation",
                   "statement": "Rule matched on the login control.", "evidence_ids": ["EV1"]}]
    assess(make_agent(database, tools, audit_entries,
                      MockLLMProvider([answer(control_assessments=controls, potential_violations=violations)])),
           incident_id)
    compliance = load(database, incident_id).compliance
    by_id = {c.control_id: c for c in compliance.controls}
    assert by_id["access_control"].status == ComplianceStatus.POTENTIAL_VIOLATION
    assert by_id["least_privilege"].status == ComplianceStatus.VIOLATION
    assert compliance.potential_violations[0].status == ComplianceStatus.POTENTIAL_VIOLATION


def test_overall_status_is_derived_by_the_backend(database, tools, audit_entries, incident_id) -> None:
    assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    compliance = load(database, incident_id).compliance
    assert compliance.overall_status == ComplianceStatus.VIOLATION
    assert "least_privilege".replace("_", " ") in compliance.overall_note.lower().replace("/", " ") or \
        "Least Privilege" in compliance.overall_note
    assert "VR-PRIV-001" in compliance.overall_note and "Derived by the backend" in compliance.overall_note


# ============================================================================ frameworks
def test_valid_framework_and_mapping_are_accepted(database, tools, incident_id) -> None:
    validate_decision(answer(), build_context(database, tools, incident_id), SETTINGS)


def test_invalid_framework_is_rejected(database, tools, incident_id) -> None:
    fa = decision()["framework_assessments"]
    fa[0]["framework"] = "ISO_9001"
    err = rejected(database, tools, incident_id, answer(framework_assessments=fa))
    assert err.code == "invalid_framework" and "ISO_9001" in err.problems[0]


def test_unknown_framework_control_mapping_is_rejected(database, tools, incident_id) -> None:
    fa = decision()["framework_assessments"]
    fa[0]["framework_control_id"] = "PR.ZZ-99"                             # framework exists, mapping does not
    err = rejected(database, tools, incident_id, answer(framework_assessments=fa))
    assert err.code == "invalid_mapping" and "PR.ZZ-99" in err.problems[0]
    fa[0].update({"framework_control_id": "A.8.2"})                        # real ISO id, wrong framework
    assert rejected(database, tools, incident_id, answer(framework_assessments=fa)).code == "invalid_mapping"


def test_framework_assessments_are_completed_from_configuration(database, tools, audit_entries, incident_id) -> None:
    assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    items = load(database, incident_id).compliance.framework_assessments
    pairs = {(x.framework, x.framework_control_id, x.control_id): x for x in items}
    assert {x.framework for x in items} == {"NIST_CSF", "ISO_27001", "SOC2", "CIS_CONTROLS"}
    written = pairs[("NIST_CSF", "PR.AA-05", "least_privilege")]
    assert written.source == "llm" and written.status == ComplianceStatus.POTENTIAL_VIOLATION
    assert written.status != ComplianceStatus.VIOLATION                    # model may not exceed... its own claim
    derived = pairs[("ISO_27001", "A.8.2", "least_privilege")]
    assert derived.source == "derived" and derived.status == ComplianceStatus.VIOLATION
    assert derived.framework_control_title == "Privileged access rights" and derived.framework_name.startswith("ISO")
    assert all((x.framework, x.framework_control_id) in {(f, c.id) for cid, ctrl in SETTINGS.mapping.controls.items()
                                                         for f, cs in ctrl.frameworks.items() for c in cs}
               for x in items)                                              # nothing outside the configuration


def test_mapping_file_cross_references_are_validated() -> None:
    data = json.loads(json.dumps({"frameworks": {"F": {"name": "F", "version": "1"}},
                                  "controls": {"c": {"name": "C", "description": "d", "triggers": {"always": True},
                                                     "frameworks": {"MISSING": [{"id": "1", "title": "t"}]}}}}))
    with pytest.raises(ValueError, match="undefined frameworks"):
        ComplianceMapping.model_validate(data)
    bad_rule = {"frameworks": {}, "controls": {}, "violation_rules": [
        {"id": "X", "control": "nope", "description": "d", "requires_event_types": ["Login"]}]}
    with pytest.raises(ValueError, match="undefined control"):
        ComplianceMapping.model_validate(bad_rule)


def test_missing_configuration_is_reported(tmp_path: Path) -> None:
    with pytest.raises(ComplianceConfigError, match="compliance_mapping.yaml"):
        load_compliance_settings(tmp_path)


# ============================================================================== reporting
def test_configured_reporting_rule_is_accepted(database, tools, audit_entries, incident_id) -> None:
    assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    compliance = load(database, incident_id).compliance
    assert compliance.reporting_status == ReportingStatus.CONFIGURED_REQUIREMENT
    by_rule = {r.rule_id: r for r in compliance.reporting_considerations}
    assert by_rule["RPT-INT-001"].source == "llm" and by_rule["RPT-INT-001"].requirement == "internal_escalation"
    assert by_rule["RPT-INT-002"].source == "configured_rule"              # matched rule the model missed
    assert {m.rule_id for m in compliance.matched_reporting_rules} == {"RPT-INT-001", "RPT-INT-002"}


@pytest.mark.parametrize("consideration", [
    {"status": "configured_requirement", "rule_id": None, "note": "Notification is legally required.", "evidence_ids": []},
    {"status": "configured_requirement", "rule_id": "RPT-LEGAL-9", "note": "A statutory duty applies.", "evidence_ids": []},
    {"status": "internal_review_recommended", "rule_id": "RPT-FAKE-1", "note": "Review it internally.", "evidence_ids": []},
])
def test_unconfigured_reporting_obligation_is_rejected(database, tools, incident_id, consideration) -> None:
    assert rejected(database, tools, incident_id,
                    answer(reporting_considerations=[consideration])).code == "semantic_invalid"


@pytest.mark.parametrize("text", [
    "This must be reported to the regulator within 72 hours.",
    "GDPR breach notification is mandatory here.",
    "This is a statutory obligation under HIPAA.",
])
def test_invented_legal_obligations_and_deadlines_are_rejected(database, tools, incident_id, text) -> None:
    consideration = [{"status": "requires_manual_assessment", "rule_id": None, "note": text, "evidence_ids": []}]
    err = rejected(database, tools, incident_id, answer(reporting_considerations=consideration))
    assert err.code == "policy_violation" and "not configured" in err.problems[0]


def test_manual_assessment_status_is_supported(database, tools) -> None:
    no_rules = SETTINGS.model_copy(update={"mapping": SETTINGS.mapping.model_copy(update={"reporting_rules": ()})})
    cloud = CloudSimulator()
    tools_ = ToolExecutor(ToolContext(cloud=cloud, database=database, registry=build_default_registry(),
                                      config_dir=CONFIG_DIR))
    audit: list = []
    incident_id = make_investigated(database, cloud, tools_, audit)
    consideration = [{"status": "requires_manual_assessment", "rule_id": None,
                      "note": "Reporting beyond configured rules needs a manual assessment.", "evidence_ids": []}]
    make_agent(database, tools_, audit, MockLLMProvider([answer(reporting_considerations=consideration)]),
               no_rules).run(ComplianceRunRequest(incident_id=incident_id))
    compliance = load(database, incident_id).compliance
    assert compliance.reporting_status == ReportingStatus.REQUIRES_MANUAL_ASSESSMENT
    assert compliance.matched_reporting_rules == []


# ==================================================================================== LLM
def test_valid_json_succeeds(database, tools, audit_entries, incident_id) -> None:
    report = assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    assert report.status == AgentRunStatus.SUCCESS and report.outcome == "compliance_assessed"
    assert report.method == TriageMethod.LLM and report.attempts == 1


@pytest.mark.parametrize("text, code", [
    ("The incident affects access control.", "invalid_json"),
    ('{"summary": ', "invalid_json"),
])
def test_malformed_json_is_rejected(database, tools, incident_id, text, code) -> None:
    assert rejected(database, tools, incident_id, text).code == code


def test_invalid_confidence_and_enums_are_rejected(database, tools, incident_id) -> None:
    assert rejected(database, tools, incident_id, answer(confidence=1.7)).code == "schema_invalid"
    assert rejected(database, tools, incident_id, answer(confidence=-3)).code == "schema_invalid"
    controls = decision()["control_assessments"]
    controls[0]["status"] = "definitely_illegal"
    assert rejected(database, tools, incident_id, answer(control_assessments=controls)).code == "schema_invalid"
    recs = decision()["recommendations"]
    recs[0]["type"] = "delete_all_users"
    assert rejected(database, tools, incident_id, answer(recommendations=recs)).code == "schema_invalid"
    data = decision()
    data["run_shell"] = "whoami"
    assert rejected(database, tools, incident_id, json.dumps(data)).code == "schema_invalid"


def test_repair_succeeds(database, tools, audit_entries, incident_id) -> None:
    mock = MockLLMProvider(["<think>hidden</think> not json", answer()])
    report = assess(make_agent(database, tools, audit_entries, mock), incident_id)
    assert report.status == AgentRunStatus.SUCCESS and report.attempts == 2
    assert report.validation_errors[0].startswith("invalid_json")
    assert "rejected by validation" in mock.calls[1]["user"]


def test_repair_fails_and_incident_is_unchanged(database, tools, audit_entries, incident_id) -> None:
    before = load(database, incident_id)
    controls = decision()["control_assessments"]
    controls[0]["control_id"] = "invented_control"
    mock = MockLLMProvider([answer(control_assessments=controls)])
    report = assess(make_agent(database, tools, audit_entries, mock), incident_id)
    assert report.status == AgentRunStatus.FAILED and report.outcome == "invalid_llm_output"
    assert len(mock.calls) == 2 and report.compliance is None                # exactly one repair, no endless retry
    assert load(database, incident_id) == before
    assert [e.result for e in audit_entries if e.action == "compliance.failed"] == ["invalid_llm_output"]


def test_ollama_unavailable(database, tools, audit_entries, incident_id) -> None:
    before = load(database, incident_id)
    report = assess(make_agent(database, tools, audit_entries, MockLLMProvider(available=False)), incident_id)
    assert report.status == AgentRunStatus.FAILED and report.outcome == "llm_unavailable"
    assert load(database, incident_id) == before
    assert assess(make_agent(database, tools, audit_entries, None), incident_id).outcome == "llm_not_configured"


def test_rule_based_fallback_is_explicit_and_conservative(database, tools, audit_entries, incident_id) -> None:
    report = assess(make_agent(database, tools, audit_entries, MockLLMProvider(available=False)), incident_id,
                    allow_rule_based_fallback=True)
    assert report.status == AgentRunStatus.SUCCESS and report.outcome == "compliance_assessed_rule_based_fallback"
    compliance = load(database, incident_id).compliance
    assert compliance.method == TriageMethod.RULE_BASED_FALLBACK and compliance.provider == "rule_based"
    assert "Rule-based fallback" in compliance.summary and report.validation_errors[0].startswith("llm_unavailable")
    assert all(c.status != ComplianceStatus.VIOLATION for c in compliance.controls)   # never claims a violation
    assert compliance.reporting_status in (ReportingStatus.CONFIGURED_REQUIREMENT,
                                           ReportingStatus.REQUIRES_MANUAL_ASSESSMENT)


# =================================================================================== security
def test_compliance_has_only_read_permissions() -> None:
    registry = build_default_registry()
    permitted = set(registry.permissions_for(AgentName.COMPLIANCE))
    assert permitted == {"get_incident", "get_resource", "get_iam_entity", "get_asset_context", "check_policy"}
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
        result = executor.execute(ToolRequest(tool_name=tool, arguments=args, requested_by=AgentName.COMPLIANCE))
        assert result.error_code == "permission_denied"
    assert cloud.get_user("alice").access_key_active and cloud.get_bucket("public-assets").public_access


def test_no_cloud_mutation(database, tools, audit_entries, incident_id, cloud) -> None:
    before = cloud.get_cloud_state()
    assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    assert cloud.get_cloud_state() == before


def test_model_cannot_smuggle_actions(database, tools, audit_entries, incident_id, cloud) -> None:
    before = cloud.get_cloud_state()
    evil = decision()
    evil["actions"] = [{"tool": "isolate_instance", "instance_id": "ec2-001"}]
    report = assess(make_agent(database, tools, audit_entries, MockLLMProvider([json.dumps(evil)])), incident_id)
    assert report.outcome == "invalid_llm_output" and cloud.get_cloud_state() == before


def test_audit_has_no_raw_output_prompts_or_secrets(database, tools, audit_entries, incident_id) -> None:
    mock = MockLLMProvider(["<think>private chain of thought</think>{", answer()])
    assess(make_agent(database, tools, audit_entries, mock), incident_id)
    dumped = json.dumps([e.model_dump(mode="json") for e in audit_entries], default=str)
    assert "chain of thought" not in dumped and SYSTEM_PROMPT[:60] not in dumped
    assert "Context (JSON)" not in dumped and not re.search(r"AKIA[A-Z0-9]{8,}", dumped)


def test_audit_records_execution_details(database, tools, audit_entries, incident_id) -> None:
    assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    mine = [e for e in audit_entries if e.actor == AgentName.COMPLIANCE]
    assert [e.action for e in mine] == ["compliance.run", "compliance.completed"]
    done = mine[-1]
    assert done.details["provider"] == "mock" and done.details["attempts"] == 1
    assert done.details["decision"]["overall_status"] == "violation"
    assert "least_privilege:violation" in done.details["decision"]["controls"]
    assert set(done.details["decision"]["frameworks"]) == {"NIST_CSF", "ISO_27001", "SOC2", "CIS_CONTROLS"}
    assert sorted(done.details["input_event_ids"]) == sorted(load(database, incident_id).related_event_ids)


# ==================================================================================== incident
def test_state_is_stored_and_previous_stages_preserved(database, tools, audit_entries, incident_id) -> None:
    before = load(database, incident_id)
    assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    after = load(database, incident_id)
    assert after.compliance is not None and after.compliance.provider == "mock"
    assert after.compliance.based_on_investigation_run == before.investigation.run_id
    assert after.triage == before.triage and after.investigation == before.investigation
    assert (after.severity, after.priority, after.category) == (before.severity, before.priority, before.category)
    assert after.mitre_techniques == before.mitre_techniques
    assert after.final_status == IncidentStatus.COMPLIANCE_ASSESSED
    assert after.current_agent == AgentName.COMPLIANCE
    assert [d.actor for d in after.agent_decisions] == [AgentName.MONITOR, AgentName.TRIAGE,
                                                        AgentName.INVESTIGATOR, AgentName.COMPLIANCE]
    assert after.remediation_plan is None and after.verification_result is None   # later stages untouched


def test_compliance_adds_new_analysis_not_a_copy_of_the_investigation(database, tools, audit_entries, incident_id) -> None:
    assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    incident = load(database, incident_id)
    c = incident.compliance
    assert c.summary != incident.investigation.summary
    assert c.controls and c.framework_assessments and c.standing_unknowns and c.affected_data
    assert not re.search(r"GDPR|HIPAA|PCI|within \d+ hours", json.dumps(c.model_dump(mode="json")), re.I)


def test_re_investigation_makes_compliance_stale(database, tools, audit_entries, incident_id) -> None:
    assess(make_agent(database, tools, audit_entries, MockLLMProvider([answer()])), incident_id)
    old = load(database, incident_id).compliance
    investigate(make_investigator(database, tools, audit_entries, MockLLMProvider([investigation_answer()])),
                incident_id)
    incident = load(database, incident_id)
    assert incident.final_status == IncidentStatus.INVESTIGATED             # back one step
    assert incident.compliance.based_on_investigation_run == old.based_on_investigation_run
    assert incident.compliance.based_on_investigation_run != incident.investigation.run_id


# ================================================================================ idempotency
def test_running_twice_is_safe_and_history_kept(database, tools, audit_entries, incident_id) -> None:
    agent = make_agent(database, tools, audit_entries,
                       MockLLMProvider([answer(), answer(confidence=0.55)]))
    first, second = assess(agent, incident_id), assess(agent, incident_id)
    incident = load(database, incident_id)
    assert incident.compliance.run_id == second.run_id != first.run_id and incident.compliance.confidence == 0.55
    assert [d.actor for d in incident.agent_decisions].count(AgentName.COMPLIANCE) == 1
    assert len(incident.compliance.controls) == 4                            # replaced, not appended
    with database.session() as session:
        stats = AgentRunService(session).stats(AgentName.COMPLIANCE.value)
    assert stats["runs"] == 2 and stats["successful_runs"] == 2 and stats["last_incident_id"] == incident_id
    done = [e for e in audit_entries if e.action == "compliance.completed"]
    assert {e.details["run_id"] for e in done} == {first.run_id, second.run_id}


def test_failed_runs_are_recorded_in_run_history(database, tools, audit_entries, incident_id) -> None:
    assess(make_agent(database, tools, audit_entries, MockLLMProvider(available=False)), incident_id)
    with database.session() as session:
        stats = AgentRunService(session).stats(AgentName.COMPLIANCE.value)
    assert stats["runs"] == 1 and stats["failed_runs"] == 1 and stats["last_result"]["outcome"] == "llm_unavailable"


# ======================================================================================= API
@pytest.fixture()
def api(cloud: CloudSimulator, database: Database):
    def build(provider) -> TestClient:
        return TestClient(create_app(cloud=cloud, database=database, settings=Settings(), llm_provider=provider))
    return build


def scripted() -> MockLLMProvider:
    return MockLLMProvider.routed({"You are the Triage Agent": [triage_answer()],
                                   "You are the Investigator Agent": [investigation_answer()],
                                   "You are the Compliance Agent": [answer()]})


def investigated_via_api(client: TestClient) -> str:
    incident_id = client.post("/api/simulation/run",
                              json={"scenario": "iam_privilege_escalation", "run_monitor": True}).json()["incident_id"]
    assert client.post("/api/agents/triage/run", json={"incident_id": incident_id}).json()["status"] == "success"
    assert client.post("/api/agents/investigator/run", json={"incident_id": incident_id}).json()["status"] == "success"
    return incident_id


def test_compliance_endpoint_full_flow(api) -> None:
    with api(scripted()) as client:
        incident_id = investigated_via_api(client)
        response = client.post("/api/agents/compliance/run", json={"incident_id": incident_id})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "success" and body["agent_result"]["agent_name"] == "Compliance Agent"
        detail = client.get(f"/api/incidents/{incident_id}").json()
        assert detail["final_status"] == "compliance_assessed" and detail["current_agent"] == "Compliance Agent"
        compliance = detail["compliance"]
        for key in ("overall_status", "summary", "affected_assets", "affected_data", "controls",
                    "framework_assessments", "control_gaps", "potential_violations", "reporting_status",
                    "reporting_considerations", "recommendations", "unknowns", "standing_unknowns", "method",
                    "provider", "model", "confidence"):
            assert key in compliance
        assert detail["triage"] and detail["investigation"]                  # preserved
        agents = client.get("/api/agents").json()
        assert agents[3]["implemented"] and agents[3]["stats"]["runs"] == 1 and agents[3]["stats"]["successful_runs"] == 1
        assert agents[3]["llm"]["provider"] == "mock" and agents[4]["implemented"] is True and agents[4]["stats"]["runs"] == 0
        assert {"compliance.run", "compliance.completed"} <= {e["action"] for e in client.get("/api/audit").json()}


@pytest.mark.parametrize("payload, status", [
    ({"incident_id": "INC-X", "unexpected": 1}, 422), ({}, 422),
    ({"incident_id": "../etc/passwd"}, 422), ({"incident_id": "INC-NOPE"}, 404)])
def test_compliance_endpoint_rejects_bad_requests(api, payload, status) -> None:
    with api(scripted()) as client:
        assert client.post("/api/agents/compliance/run", json=payload).status_code == status


def test_compliance_endpoint_requires_investigation(api) -> None:
    with api(scripted()) as client:
        incident_id = client.post("/api/simulation/run", json={"scenario": "iam_privilege_escalation",
                                                               "run_monitor": True}).json()["incident_id"]
        client.post("/api/agents/triage/run", json={"incident_id": incident_id})   # triaged only
        body = client.post("/api/agents/compliance/run", json={"incident_id": incident_id}).json()
        assert body["status"] == "skipped" and body["outcome"] == "investigation_required"
        detail = client.get(f"/api/incidents/{incident_id}").json()
        assert detail["compliance"] is None and detail["investigation"] is None   # nothing was run implicitly


def test_compliance_endpoint_llm_unavailable(api) -> None:
    provider = MockLLMProvider.routed({"You are the Triage Agent": [triage_answer()],
                                       "You are the Investigator Agent": [investigation_answer()]})
    with api(provider) as client:
        incident_id = investigated_via_api(client)
        down = MockLLMProvider(available=False)
        client.app.state.llm = down
        body = client.post("/api/agents/compliance/run", json={"incident_id": incident_id}).json()
        assert body["status"] == "failed" and body["outcome"] == "llm_unavailable" and body["compliance"] is None
        assert client.get(f"/api/incidents/{incident_id}").json()["compliance"] is None
        assert client.get("/api/agents").json()[3]["stats"]["failed_runs"] == 1
        assert "compliance.failed" in [e["action"] for e in client.get("/api/audit").json()]


def test_compliance_endpoint_response_validates(api) -> None:
    from app.agents.compliance.agent import ComplianceRunReport
    with api(scripted()) as client:
        body = client.post("/api/agents/compliance/run", json={"incident_id": investigated_via_api(client)}).json()
    assert ComplianceRunReport.model_validate(body).compliance is not None


def test_compliance_endpoint_503_without_configuration(cloud, database, tmp_path: Path) -> None:
    with TestClient(create_app(cloud=cloud, database=database, settings=Settings(config_dir=tmp_path),
                               llm_provider=scripted())) as client:
        assert client.post("/api/agents/compliance/run", json={"incident_id": "INC-1"}).status_code == 503


def test_earlier_agents_never_trigger_compliance(api) -> None:
    with api(scripted()) as client:
        incident_id = investigated_via_api(client)
        assert client.get(f"/api/incidents/{incident_id}").json()["compliance"] is None
        assert client.get("/api/agents").json()[3]["stats"]["runs"] == 0
