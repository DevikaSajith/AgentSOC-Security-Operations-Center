import pytest

from app.simulator.attacks import AttackSimulator, UnknownScenarioError
from app.simulator.cloud import CloudSimulator


def types(result) -> list[str]:
    return [e.event_type for e in result.events]


def test_iam_attack_sequence_and_state(cloud: CloudSimulator, attacks: AttackSimulator) -> None:
    result = attacks.run("iam_privilege_escalation")
    assert types(result) == ["Login", "CreateAccessKey", "AttachAdminPolicy", "GetSecretValue"]
    assert {e.user for e in result.events} == {"alice"}
    assert len({e.source_ip for e in result.events}) == 1
    assert cloud.get_user("alice").admin is True
    assert len(cloud.get_user("alice").access_keys) == 2
    change = next(c for c in result.state_changes if c.action == "make_user_admin")
    assert change.old_state == {"admin": False} and change.new_state == {"admin": True}
    assert result.cloud_state_changed is True


def test_s3_attack_changes_bucket_state(cloud: CloudSimulator, attacks: AttackSimulator) -> None:
    assert cloud.get_bucket("company-data").public_access is False
    result = attacks.run("public_s3_exposure")
    assert types(result) == ["Login", "PutBucketPolicy", "DeletePublicAccessBlock", "GetObject"]
    assert cloud.get_bucket("company-data").public_access is True


def test_ec2_attack_events_and_isolatable(cloud: CloudSimulator, attacks: AttackSimulator) -> None:
    result = attacks.run("ec2_compromise")
    assert types(result) == ["Login", "ExecuteCommand", "AssumeRole", "NetworkFlowAnomaly"]
    assert cloud.get_instance("ec2-001").iam_role == "ec2-admin-role"
    cloud.isolate_instance("ec2-001")
    assert cloud.get_instance("ec2-001").status == "isolated"


def test_credential_misuse_uses_normal_then_suspicious_ip(attacks: AttackSimulator) -> None:
    result = attacks.run("credential_misuse")
    first, second = result.events[0], result.events[1]
    assert (first.event_type, second.event_type) == ("Login", "Login")
    assert first.source_ip != second.source_ip
    assert result.events[-1].details["sensitive"] is True


@pytest.mark.parametrize("name", ["iam_privilege_escalation", "public_s3_exposure",
                                  "ec2_compromise", "credential_misuse"])
def test_scenario_result_shape(attacks: AttackSimulator, name: str) -> None:
    result = attacks.run(name)
    assert result.scenario_name == name and result.scenario_id and result.description
    assert len(result.events) == 4 and result.affected_resources
    assert result.attack_start_time <= result.attack_end_time
    stamps = [e.timestamp for e in result.events]
    assert stamps == sorted(stamps)
    assert {e.details["scenario_id"] for e in result.events} == {result.scenario_id}


def test_unknown_scenario(attacks: AttackSimulator) -> None:
    with pytest.raises(UnknownScenarioError):
        attacks.run("nope")
