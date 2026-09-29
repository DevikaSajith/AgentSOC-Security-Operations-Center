"""Unit tests for each Monitor Agent stage in isolation (no database, no API)."""

from datetime import timedelta

import pytest

from app.agents.monitor.correlation import correlate
from app.agents.monitor.decision import confidence_for, decide
from app.agents.monitor.dedup import deduplicate
from app.agents.monitor.enrichment import Enricher
from app.agents.monitor.fingerprint import fingerprint
from app.agents.monitor.models import UNKNOWN_PRINCIPAL, UNSPECIFIED_IP
from app.agents.monitor.normalizer import EventNormalizer, EventRejection
from app.domain.enums import EventSource, IncidentCategory, Priority, Severity
from app.simulator.attacks import AttackSimulator
from app.simulator.cloud import CloudSimulator
from tests.monitor_fixtures import (
    ALICE_IP,
    ATTACKER_IP,
    cloudtrail,
    config,
    event,
    guardduty_finding,
    normalized,
    security_hub_finding,
    vpc_flow,
)

CFG = config()


@pytest.fixture()
def normalizer() -> EventNormalizer:
    return EventNormalizer(CFG)


def rejected(normalizer: EventNormalizer, raw) -> EventRejection:
    with pytest.raises(EventRejection) as info:
        normalizer.normalize_raw(raw)
    return info.value


# ======================================================================= validation
def test_valid_simulator_event_is_accepted(normalizer: EventNormalizer) -> None:
    source = event("CreateAccessKey")
    result = normalizer.normalize_raw(source.model_dump(mode="json"))
    assert result.event.event_id == source.event_id
    assert result.event.severity == Severity.MEDIUM  # the supplied severity is preserved
    assert result.ingest_format == "security_event" and len(result.fingerprint) == 64
    assert result.event.details["ingest"] == {"format": "security_event", "origin": "submitted"}


@pytest.mark.parametrize("raw, reason", [
    ("not an object", "schema_invalid"),
    ({"hello": "world"}, "unrecognized_format"),
    ({**event("Login").model_dump(mode="json"), "source_ip": "999.1.1.1"}, "schema_invalid"),
    ({**event("Login").model_dump(mode="json"), "severity": "apocalyptic"}, "invalid_severity"),
    ({**event("Login").model_dump(mode="json"), "timestamp": "yesterday"}, "invalid_timestamp"),
    ({**event("Login").model_dump(mode="json"), "timestamp": None}, "missing_timestamp"),
])
def test_malformed_events_are_rejected(normalizer: EventNormalizer, raw, reason: str) -> None:
    assert rejected(normalizer, raw).reason == reason


def test_rejection_detail_never_echoes_values(normalizer: EventNormalizer) -> None:
    raw = {**event("Login").model_dump(mode="json"), "source_ip": "SECRET-VALUE"}
    assert "SECRET-VALUE" not in rejected(normalizer, raw).detail


@pytest.mark.parametrize("missing", ["event_id"])
def test_missing_identifier_is_rejected(normalizer: EventNormalizer, missing: str) -> None:
    raw = event("Login").model_dump(mode="json")
    del raw[missing]
    assert rejected(normalizer, raw).reason == "missing_identifier"


def test_cloudtrail_without_event_id_is_rejected(normalizer: EventNormalizer) -> None:
    raw = cloudtrail("ConsoleLogin", "signin.amazonaws.com", {})
    del raw["eventID"]
    assert rejected(normalizer, raw).reason == "missing_identifier"


def test_event_without_principal_or_resource_is_rejected(normalizer: EventNormalizer) -> None:
    raw = {**event("ListBuckets").model_dump(mode="json"), "user": UNKNOWN_PRINCIPAL}
    raw.pop("principal_id")
    assert rejected(normalizer, raw).reason == "missing_identifier"  # resource is '*'


def test_unsupported_source_is_rejected(normalizer: EventNormalizer) -> None:
    raw = {**event("Login").model_dump(mode="json"), "source": "Splunk"}
    err = rejected(normalizer, raw)
    assert err.reason == "unsupported_source" and "CloudTrail" in err.detail


def test_service_native_sources_are_supported(normalizer: EventNormalizer) -> None:
    for source in ("IAM", "EC2", "S3", "GuardDuty", "Security Hub"):
        raw = {**event("Login").model_dump(mode="json"), "source": source,
               "event_id": f"native-{source}"}
        assert normalizer.normalize_raw(raw).event.source == EventSource(source)


def test_future_and_stale_timestamps_are_rejected(normalizer: EventNormalizer) -> None:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    future = {**event("Login").model_dump(mode="json"),
              "timestamp": (now + timedelta(hours=1)).isoformat()}
    stale = {**event("Login").model_dump(mode="json"),
             "timestamp": (now - timedelta(days=45)).isoformat()}
    assert rejected(normalizer, future).reason == "invalid_timestamp"
    assert rejected(normalizer, stale).reason == "stale_event"


def test_missing_severity_is_derived_from_config(normalizer: EventNormalizer) -> None:
    raw = event("AttachAdminPolicy").model_dump(mode="json")
    del raw["severity"]
    assert normalizer.normalize_raw(raw).event.severity == Severity.HIGH
    raw = event("ListUsers", resource="alice").model_dump(mode="json")
    del raw["severity"]
    assert normalizer.normalize_raw(raw).event.severity == Severity.INFO


# ==================================================================== normalization
def test_cloudtrail_login_is_normalized(normalizer: EventNormalizer) -> None:
    raw = cloudtrail("ConsoleLogin", "signin.amazonaws.com", {}, event_id="ct-login-1")
    result = normalizer.normalize_raw(raw).event
    assert (result.event_id, result.source, result.event_type) == (
        "ct-login-1", EventSource.CLOUDTRAIL, "ConsoleLogin")
    assert result.principal_id == "alice" and result.source_ip == ATTACKER_IP
    assert (result.resource_type, result.resource_id) == ("IAMUser", "alice")
    assert result.account_id == "123456789012" and result.region == "us-east-1"
    assert result.raw_event == raw  # the original record is kept verbatim
    assert result.action == "console_login"


def test_iam_cloudtrail_event_is_normalized(normalizer: EventNormalizer) -> None:
    raw = cloudtrail("AttachUserPolicy", "iam.amazonaws.com",
                     {"userName": "ci-deploy", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    result = normalizer.normalize_raw(raw).event
    assert (result.resource_type, result.resource_id) == ("IAMUser", "ci-deploy")
    assert result.principal_id == "alice"  # who did it, not who it was done to
    assert result.details["request_parameters"]["userName"] == "ci-deploy"


def test_ec2_cloudtrail_event_is_normalized(normalizer: EventNormalizer) -> None:
    single = cloudtrail("ModifyInstanceAttribute", "ec2.amazonaws.com", {"instanceId": "ec2-001"},
                        event_id="ct-ec2-1")
    listed = cloudtrail("StopInstances", "ec2.amazonaws.com",
                        {"instancesSet": {"items": [{"instanceId": "ec2-002"}]}}, event_id="ct-ec2-2")
    sg = cloudtrail("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", {"groupId": "sg-web"},
                    event_id="ct-ec2-3")
    assert normalizer.normalize_raw(single).event.resource_id == "ec2-001"
    assert normalizer.normalize_raw(listed).event.resource_type == "EC2Instance"
    assert normalizer.normalize_raw(listed).event.resource_id == "ec2-002"
    sg_event = normalizer.normalize_raw(sg).event
    assert (sg_event.resource_type, sg_event.severity) == ("SecurityGroup", Severity.MEDIUM)


def test_s3_cloudtrail_event_is_normalized(normalizer: EventNormalizer) -> None:
    raw = cloudtrail("DeletePublicAccessBlock", "s3.amazonaws.com", {"bucketName": "company-data"})
    result = normalizer.normalize_raw(raw).event
    assert (result.resource_type, result.resource_id) == ("S3Bucket", "company-data")
    assert result.severity == Severity.HIGH  # CloudTrail has no severity -> config default


def test_aws_service_caller_gets_unspecified_ip(normalizer: EventNormalizer) -> None:
    raw = cloudtrail("AssumeRole", "sts.amazonaws.com", {}, ip="ec2.amazonaws.com")
    assert normalizer.normalize_raw(raw).event.source_ip == UNSPECIFIED_IP


def test_guardduty_finding_is_normalized(normalizer: EventNormalizer) -> None:
    result = normalizer.normalize_raw(guardduty_finding()).event
    assert result.source == EventSource.GUARDDUTY and result.severity == Severity.HIGH
    assert (result.resource_type, result.resource_id) == ("EC2Instance", "ec2-001")
    assert result.source_ip == "192.0.2.145" and result.principal_id == UNKNOWN_PRINCIPAL
    assert rejected(normalizer, guardduty_finding(severity="bad")).reason == "invalid_severity"


def test_security_hub_finding_is_normalized(normalizer: EventNormalizer) -> None:
    raw = security_hub_finding()
    result = normalizer.normalize_raw(raw).event
    assert result.source == EventSource.SECURITY_HUB and result.severity == Severity.HIGH
    assert (result.resource_type, result.resource_id) == ("S3Bucket", "company-data")
    # the long ARN id gets a stable short form that fits the event store
    assert result.event_id.startswith("id-") and len(result.event_id) == 36
    assert normalizer.normalize_raw(raw).event.event_id == result.event_id


def test_vpc_flow_log_is_normalized(normalizer: EventNormalizer) -> None:
    result = normalizer.normalize_raw(vpc_flow()).event
    assert result.source == EventSource.VPC_FLOW_LOGS and result.event_type == "NetworkFlow"
    assert result.resource_id == "ec2-001" and result.details["dstport"] == 4444
    assert result.event_id == normalizer.normalize_raw(vpc_flow()).event.event_id  # derived
    assert rejected(normalizer, vpc_flow(**{"resource-id": None})).reason == "missing_identifier"


# ==================================================================== fingerprints
def test_fingerprint_ignores_key_order_and_copy_ids(normalizer: EventNormalizer) -> None:
    raw = cloudtrail("PutBucketPolicy", "s3.amazonaws.com", {"bucketName": "company-data", "a": 1})
    reordered = dict(reversed(list(raw.items())))
    reordered["requestParameters"] = {"a": 1, "bucketName": "company-data"}
    redelivered = {**raw, "eventID": "ct-other-copy"}
    fps = {normalizer.normalize_raw(r).fingerprint for r in (raw, reordered, redelivered)}
    assert len(fps) == 1


def test_fingerprint_is_stable_across_storage_round_trip() -> None:
    original = event("CreateAccessKey")
    restored = type(original).model_validate(original.model_dump(mode="json"))
    assert fingerprint(original) == fingerprint(restored)


@pytest.mark.parametrize("change", [
    {"at": 1}, {"ip": "198.51.100.77"}, {"user": "bob"}, {"resource": "bob"}])
def test_different_events_get_different_fingerprints(change: dict) -> None:
    base = {"at": 0, "ip": ATTACKER_IP, "user": "alice", "resource": "alice"}
    assert fingerprint(event("CreateAccessKey", **base)) != \
        fingerprint(event("CreateAccessKey", **{**base, **change}))


# ==================================================================== deduplication
def test_exact_duplicate_in_batch_is_detected() -> None:
    first = event("CreateAccessKey")
    copy = first.model_copy(update={"event_id": "copy-1"})
    raw_copy = copy.model_copy(update={"raw_event": {**copy.raw_event, "eventID": "copy-1"}})
    result = deduplicate([normalized(first), normalized(raw_copy)], set(), {})
    assert [n.event.event_id for n in result.unique] == [first.event_id]
    assert result.duplicates[0].model_dump() == {"event_id": "copy-1", "duplicate_of": first.event_id,
                                                 "kind": "in_batch"}


def test_duplicate_of_previously_processed_event() -> None:
    old = normalized(event("CreateAccessKey"))
    replay = old.model_copy(update={"event": old.event.model_copy(update={"event_id": "replay"})})
    result = deduplicate([replay], set(), {old.fingerprint: old.event.event_id})
    assert result.unique == [] and result.duplicates[0].kind == "previously_processed"


def test_already_processed_ids_are_skipped_not_duplicates() -> None:
    item = normalized(event("Login"))
    result = deduplicate([item], {item.event.event_id}, {item.fingerprint: item.event.event_id})
    assert result.already_processed == [item.event.event_id] and not result.duplicates


def test_similar_but_different_events_are_not_deduplicated() -> None:
    items = [normalized(event("GetObject", resource="company-data", at=t)) for t in (0, 5, 10)]
    assert len(deduplicate(items, set(), {}).unique) == 3


# ====================================================================== correlation
def ids(groups) -> list[list[str]]:
    return [[n.event.event_id for n in g] for g in groups]


def test_related_events_are_grouped() -> None:
    items = [normalized(event(t, at=i * 20)) for i, t in enumerate(
        ["Login", "CreateAccessKey", "AttachAdminPolicy", "GetSecretValue"])]
    groups = correlate(items, CFG.correlation.window_seconds)
    assert len(groups) == 1 and len(groups[0]) == 4


def test_ip_change_is_linked_through_the_shared_resource() -> None:
    login_home = normalized(event("Login", ip=ALICE_IP, at=0))           # resource: alice
    login_away = normalized(event("Login", ip=ATTACKER_IP, at=30))       # resource: alice
    listing = normalized(event("ListBuckets", ip=ATTACKER_IP, at=60))    # resource: *
    assert len(correlate([login_home, login_away, listing], 900)) == 1


def test_unrelated_events_stay_separate() -> None:
    alice = normalized(event("CreateAccessKey", user="alice", at=0))
    bob = normalized(event("CreateAccessKey", user="bob", ip=ATTACKER_IP, at=1))  # same IP, other user
    wildcard_a = normalized(event("ListBuckets", user="alice", ip=ALICE_IP, at=2))
    wildcard_b = normalized(event("ListBuckets", user="alice", ip="203.0.113.99", at=3))
    groups = correlate([alice, bob, wildcard_a, wildcard_b], 900)
    assert len(groups) == 4  # '*' is never a shared resource; different IPs don't link


def test_time_window_splits_groups() -> None:
    inside = [normalized(event("Login", at=0)), normalized(event("CreateAccessKey", at=899))]
    outside = [normalized(event("Login", at=0)), normalized(event("CreateAccessKey", at=901))]
    assert len(correlate(inside, 900)) == 1
    assert len(correlate(outside, 900)) == 2


def test_window_chains_through_intermediate_events() -> None:
    items = [normalized(event("Login", at=t)) for t in (0, 800, 1600)]
    assert len(correlate(items, 900)) == 1  # each link <= window, total span > window


def test_correlation_is_order_independent() -> None:
    items = [normalized(event(t, at=i * 10)) for i, t in enumerate(["Login", "CreateAccessKey"])]
    assert ids(correlate(items, 900)) == ids(correlate(list(reversed(items)), 900))


# ============================================================ enrichment + decision
def group_for(events, cloud: CloudSimulator | None = None):
    lookup = None
    if cloud is not None:
        lookup = lambda t, i: cloud.get_user(i).model_dump(mode="json") if t == "IAMUser" else None  # noqa: E731
    return Enricher(CFG, lookup).build_group([normalized(e) for e in events])


def test_suspicious_event_creates_incident_decision() -> None:
    decision = decide(group_for([event("AttachAdminPolicy")]), CFG)
    assert decision.create_incident and "suspicious_event_type" in decision.rules_matched
    assert decision.severity == Severity.HIGH and decision.priority == Priority.P2
    assert decision.category == IncidentCategory.IAM


def test_benign_activity_does_not_create_incident() -> None:
    group = group_for([event("Login", ip=ALICE_IP), event("ListUsers", ip=ALICE_IP, at=5)])
    decision = decide(group, CFG)
    assert not decision.create_incident and decision.confidence == 0.0
    assert decision.reason == "no security indicators; routine activity"


def test_single_weak_signal_stays_below_threshold() -> None:
    decision = decide(group_for([event("Login", ip=ATTACKER_IP)]), CFG)
    assert not decision.create_incident and decision.indicators == ["untrusted_source_ip"]


def test_weak_signals_correlated_create_incident_with_severity_floor() -> None:
    cloud = CloudSimulator()
    result = AttackSimulator(cloud).run("credential_misuse")
    decision = decide(group_for(result.events, cloud), CFG)
    assert decision.rules_matched == ["correlated_suspicious_group"]
    assert decision.category == IncidentCategory.CREDENTIAL
    assert decision.severity == Severity.MEDIUM  # all events are 'info': floor applies
    assert {"untrusted_source_ip", "sensitive_resource", "principal_ip_change"} <= set(decision.indicators)


def test_privileged_principal_comes_from_cloud_state() -> None:
    cloud = CloudSimulator()
    cloud.make_user_admin("alice")
    group = group_for([event("CreateAccessKey")], cloud)
    assert "privileged_principal" in group.group_indicators
    assert group.resource_context["IAMUser/alice"]["admin"] is True


def test_confidence_is_monotonic_noisy_or() -> None:
    one = confidence_for(["untrusted_source_ip"], CFG)
    two = confidence_for(["untrusted_source_ip", "sensitive_resource"], CFG)
    assert one == 0.3 and two == pytest.approx(0.51) and two > one
    assert confidence_for(list(CFG.confidence.indicator_weights), CFG) <= CFG.confidence.max_confidence
    assert confidence_for(["untrusted_source_ip", "untrusted_source_ip"], CFG) == one
