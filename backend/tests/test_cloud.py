import pytest

from app.simulator.cloud import CloudSimulator, ResourceNotFoundError


def test_cloud_initializes_correctly(cloud: CloudSimulator) -> None:
    state = cloud.get_cloud_state()
    assert set(state) == {"iam_users", "ec2_instances", "s3_buckets"}


def test_iam_users_exist(cloud: CloudSimulator) -> None:
    for name in ("alice", "bob"):
        user = cloud.get_user(name)
        assert user.role == "developer"
        assert user.admin is False
        assert user.access_key_active is True


def test_ec2_instances_exist(cloud: CloudSimulator) -> None:
    assert cloud.get_instance("ec2-001").private_ip == "10.0.1.10"
    assert cloud.get_instance("ec2-002").private_ip == "10.0.1.11"
    assert cloud.get_instance("ec2-001").status == "running"


def test_s3_buckets_exist(cloud: CloudSimulator) -> None:
    assert cloud.get_bucket("company-data").public_access is False
    assert cloud.get_bucket("public-assets").public_access is True


def test_access_key_can_be_disabled_and_enabled(cloud: CloudSimulator) -> None:
    result = cloud.disable_access_key("alice")
    assert result.success and result.action == "disable_access_key"
    assert result.old_state == {"access_key_active": True}
    assert result.new_state == {"access_key_active": False}
    assert cloud.get_user("alice").access_key_active is False
    cloud.enable_access_key("alice")
    assert cloud.get_user("alice").access_key_active is True


def test_instance_can_be_isolated_and_restored(cloud: CloudSimulator) -> None:
    result = cloud.isolate_instance("ec2-001")
    assert result.old_state["status"] == "running" and result.new_state["status"] == "isolated"
    assert cloud.get_instance("ec2-001").status == "isolated"
    cloud.restore_instance("ec2-001")
    assert cloud.get_instance("ec2-001").status == "running"


def test_bucket_can_be_made_private(cloud: CloudSimulator) -> None:
    result = cloud.make_bucket_private("public-assets")
    assert result.old_state == {"public_access": True}
    assert cloud.get_bucket("public-assets").public_access is False


def test_admin_grant_and_revoke(cloud: CloudSimulator) -> None:
    cloud.make_user_admin("bob")
    assert cloud.get_user("bob").admin is True
    cloud.remove_admin_privileges("bob")
    assert cloud.get_user("bob").admin is False


def test_action_result_has_required_fields(cloud: CloudSimulator) -> None:
    dumped = cloud.make_bucket_public("company-data").model_dump()
    for key in ("success", "resource", "action", "old_state", "new_state", "timestamp"):
        assert key in dumped


def test_unknown_resource_raises(cloud: CloudSimulator) -> None:
    with pytest.raises(ResourceNotFoundError):
        cloud.get_user("mallory")
    with pytest.raises(ResourceNotFoundError):
        cloud.isolate_instance("ec2-999")


def test_reset_restores_initial_state(cloud: CloudSimulator) -> None:
    cloud.make_user_admin("alice")
    cloud.isolate_instance("ec2-002")
    cloud.reset()
    assert cloud.get_user("alice").admin is False
    assert cloud.get_instance("ec2-002").status == "running"
