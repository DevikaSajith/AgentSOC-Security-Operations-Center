import pytest
from pydantic import ValidationError

from app.domain import (
    AgentAction,
    AgentName,
    AgentResult,
    AgentRunStatus,
    ApprovalStatus,
    EventSource,
    Evidence,
    HumanActor,
    IncidentState,
    IncidentStatus,
    MitreTechnique,
    ProposedAction,
    RemediationPlan,
    RemediationStep,
    normalize_agent_name,
)


def make_incident(**overrides) -> IncidentState:
    fields = {"title": "Admin policy attached", "source": EventSource.CLOUDTRAIL,
              "event_type": "AttachAdminPolicy"}
    return IncidentState(**{**fields, **overrides})


# ---------------------------------------------------------------- IncidentState
def test_incident_defaults_are_safe() -> None:
    incident = make_incident()
    assert incident.incident_id.startswith("INC-")
    assert incident.final_status == IncidentStatus.NEW
    assert incident.approval_required is False
    assert incident.approval_status == ApprovalStatus.NOT_REQUIRED
    assert incident.remediation_plan is None and incident.audit_log == []


def test_incident_round_trips_through_json() -> None:
    incident = make_incident(
        mitre_techniques=[MitreTechnique(technique_id="T1098.001", name="Account Manipulation",
                                         tactic="Privilege Escalation", confidence=0.8)],
        remediation_plan=RemediationPlan(steps=[RemediationStep(
            tool_name="remove_admin_privileges", arguments={"username": "alice"})]),
        approval_required=True, approval_status=ApprovalStatus.PENDING,
        current_agent=AgentName.REMEDIATION)
    restored = IncidentState.model_validate_json(incident.model_dump_json())
    assert restored == incident


@pytest.mark.parametrize("bad", [
    {"confidence": 1.5},
    {"source": "Splunk"},
    {"severity": "catastrophic"},
    {"final_status": "done"},
    {"title": ""},
    {"current_agent": "Detection Agent"},  # legacy names are not valid in new data
])
def test_incident_rejects_invalid_values(bad: dict) -> None:
    with pytest.raises(ValidationError):
        make_incident(**bad)


def test_approval_fields_must_agree() -> None:
    with pytest.raises(ValidationError):
        make_incident(approval_required=True)  # status still 'not_required'
    with pytest.raises(ValidationError):
        make_incident(approval_status=ApprovalStatus.APPROVED)  # approval not required


def test_mitre_technique_id_format() -> None:
    with pytest.raises(ValidationError):
        MitreTechnique(technique_id="1098", name="x", tactic="y")


# ------------------------------------------------------------------ AgentResult
def test_agent_result_contract() -> None:
    result = AgentResult(
        agent_name=AgentName.TRIAGE, incident_id="INC-1", status=AgentRunStatus.SUCCESS,
        confidence=0.9, findings=["admin policy attached from unusual IP"],
        evidence=[Evidence(kind="event", description="AttachAdminPolicy", event_id="e1")],
        actions=[AgentAction(action="create_incident", target="INC-1")],
        proposed_actions=[ProposedAction(tool_name="get_asset_context",
                                         arguments={"resource_id": "alice"})])
    assert result.errors == [] and result.timestamp.tzinfo is not None
    with pytest.raises(ValidationError):  # actions are machine-readable identifiers
        AgentAction(action="Created an incident!")


def test_failed_agent_result_needs_errors() -> None:
    with pytest.raises(ValidationError):
        AgentResult(agent_name=AgentName.MONITOR, incident_id="INC-1",
                    status=AgentRunStatus.FAILED, confidence=0.0)


def test_agent_result_rejects_unknown_agent_and_bad_confidence() -> None:
    with pytest.raises(ValidationError):
        AgentResult(agent_name="Response Agent", incident_id="INC-1",
                    status=AgentRunStatus.SUCCESS, confidence=0.5)
    with pytest.raises(ValidationError):
        AgentResult(agent_name=AgentName.MONITOR, incident_id="INC-1",
                    status=AgentRunStatus.SUCCESS, confidence=-0.1)


# ------------------------------------------------------------------ agent names
def test_agent_names_and_ids() -> None:
    assert [a.value for a in AgentName] == ["Monitor Agent", "Triage Agent",
                                            "Investigator Agent", "Compliance Agent",
                                            "Remediation Agent"]
    assert AgentName.INVESTIGATOR.agent_id == "investigator"


@pytest.mark.parametrize("legacy, current", [
    ("Detection Agent", AgentName.MONITOR),
    ("Investigation Agent", AgentName.INVESTIGATOR),
    ("Validation Agent", AgentName.COMPLIANCE),
    ("Response Agent", AgentName.REMEDIATION),
    ("triage", AgentName.TRIAGE),
    ("Remediation Agent", AgentName.REMEDIATION),
])
def test_legacy_agent_names_normalize(legacy: str, current: AgentName) -> None:
    assert normalize_agent_name(legacy) == current


def test_unknown_agent_name_rejected() -> None:
    with pytest.raises(ValueError):
        normalize_agent_name("Rogue Agent")
    assert HumanActor.ANALYST.value == "Human Analyst"
