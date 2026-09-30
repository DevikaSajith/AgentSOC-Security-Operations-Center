"""Deterministic feature extraction from an enriched Monitor event group.

Input: an EventGroup (events + the Monitor's per-event indicators + group indicators + cloud context).
Output: a fixed-order numeric vector. Only COUNTS, RATIOS and FLAGS: no principal names, IP addresses, resource
identifiers, event ids, details or anything credential-like reaches the model. Simulator ground truth
(scenario_id / step / state_change) is never read, so it cannot leak into training. Missing values are 0.
"""

from datetime import datetime
from typing import Any

from app.agents.monitor.enrichment import SEVERITY_RANK
from app.agents.monitor.models import EventGroup
from app.domain.enums import EventSource

FEATURE_VERSION = "f1"

FEATURES: dict[str, str] = {
    "event_count": "number of events in the correlated group",
    "duration_seconds": "time between the first and last event",
    "event_frequency_per_min": "events per minute (window at least one minute)",
    "burst_events_60s": "most events inside any 60-second window",
    "min_gap_seconds": "shortest gap between consecutive events (0 with one event)",
    "mean_gap_seconds": "average gap between consecutive events (0 with one event)",
    "max_severity_rank": "highest source severity (0 info ... 4 critical)",
    "mean_severity_rank": "average source severity",
    "high_severity_count": "events with the Monitor's high_severity indicator",
    "suspicious_api_count": "events whose API call is on the suspicious list",
    "sensitive_resource_count": "events touching a sensitive resource",
    "untrusted_ip_count": "events from an untrusted source IP",
    "untrusted_ip_ratio": "share of events from an untrusted source IP",
    "unique_source_ips": "distinct source IPs",
    "unique_resources": "distinct resources touched",
    "principal_ip_change": "same principal seen from trusted and untrusted IPs (0/1)",
    "privileged_principal": "the acting IAM user currently has admin rights (0/1)",
    "network_event_count": "network / flow-log events",
    "correlated_event_count": "events when the Monitor correlated them, else 0",
    "independent_signal_count": "distinct rule signals (excluding correlation and ML)",
    "n_login": "Login events",
    "n_create_access_key": "CreateAccessKey events",
    "n_attach_admin_policy": "AttachAdminPolicy events",
    "n_get_secret_value": "GetSecretValue events",
    "n_put_bucket_policy": "PutBucketPolicy events",
    "n_delete_public_access_block": "DeletePublicAccessBlock events",
    "n_get_object": "GetObject events",
    "n_list_or_describe": "List*/Describe*/GetCallerIdentity events",
    "n_execute_command": "ExecuteCommand events",
    "n_assume_role": "AssumeRole events",
    "n_network_flow_anomaly": "NetworkFlowAnomaly events",
    "n_res_iam": "events on IAM users",
    "n_res_s3": "events on S3 buckets",
    "n_res_ec2": "events on EC2 instances",
    "n_res_secret": "events on secrets",
}
FEATURE_NAMES: tuple[str, ...] = tuple(FEATURES)

_TYPE_COUNTERS = {
    "Login": "n_login", "CreateAccessKey": "n_create_access_key", "AttachAdminPolicy": "n_attach_admin_policy",
    "GetSecretValue": "n_get_secret_value", "PutBucketPolicy": "n_put_bucket_policy",
    "DeletePublicAccessBlock": "n_delete_public_access_block", "GetObject": "n_get_object",
    "ListBuckets": "n_list_or_describe", "ListUsers": "n_list_or_describe", "DescribeInstances": "n_list_or_describe",
    "GetCallerIdentity": "n_list_or_describe", "ExecuteCommand": "n_execute_command", "AssumeRole": "n_assume_role",
    "NetworkFlowAnomaly": "n_network_flow_anomaly",
}
_RESOURCE_COUNTERS = {"IAMUser": "n_res_iam", "S3Bucket": "n_res_s3", "EC2Instance": "n_res_ec2", "Secret": "n_res_secret"}
_NON_SIGNALS = {"correlated_group", "ml_threat_predicted"}  # never feed the model's own output back to it


class FeatureError(ValueError):
    """The group cannot be turned into features (empty or malformed)."""


def _seconds(a: datetime, b: datetime) -> float:
    return abs((b - a).total_seconds())


def extract_features(group: EventGroup) -> dict[str, float]:
    """A complete feature dict (every name in FEATURE_NAMES). Raises FeatureError for an empty group."""
    if not group.events:
        raise FeatureError("an event group must contain at least one event")
    f: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
    events = sorted(group.events, key=lambda e: e.event.timestamp)
    count = len(events)
    stamps = [e.event.timestamp for e in events]
    duration = _seconds(stamps[0], stamps[-1])
    f["event_count"] = float(count)
    f["duration_seconds"] = duration
    f["event_frequency_per_min"] = count / (max(duration, 60.0) / 60.0)
    gaps = [_seconds(a, b) for a, b in zip(stamps, stamps[1:])]
    f["min_gap_seconds"], f["mean_gap_seconds"] = (min(gaps), sum(gaps) / len(gaps)) if gaps else (0.0, 0.0)
    f["burst_events_60s"] = float(max(sum(1 for t in stamps if 0 <= _seconds(s, t) <= 60 and t >= s) for s in stamps))
    ranks = [SEVERITY_RANK[e.event.severity] for e in events]
    f["max_severity_rank"], f["mean_severity_rank"] = float(max(ranks)), sum(ranks) / count
    f["high_severity_count"] = float(sum("high_severity" in e.indicators for e in events))
    f["suspicious_api_count"] = float(sum("suspicious_event_type" in e.indicators for e in events))
    f["sensitive_resource_count"] = float(sum("sensitive_resource" in e.indicators for e in events))
    untrusted = sum("untrusted_source_ip" in e.indicators for e in events)
    f["untrusted_ip_count"], f["untrusted_ip_ratio"] = float(untrusted), untrusted / count
    f["unique_source_ips"] = float(len({e.event.source_ip for e in events}))
    f["unique_resources"] = float(len({(e.event.resource_type, e.event.resource_id) for e in events}))
    f["principal_ip_change"] = float("principal_ip_change" in group.group_indicators)
    f["privileged_principal"] = float("privileged_principal" in group.group_indicators)
    f["network_event_count"] = float(sum(e.event.source == EventSource.VPC_FLOW_LOGS
                                         or e.event.event_type == "NetworkFlowAnomaly" for e in events))
    f["correlated_event_count"] = float(count if "correlated_group" in group.group_indicators else 0)
    f["independent_signal_count"] = float(len({i for i in group.indicators() if i not in _NON_SIGNALS}))
    for item in events:
        counter = _TYPE_COUNTERS.get(item.event.event_type)
        if counter:
            f[counter] += 1.0
        resource = _RESOURCE_COUNTERS.get(item.event.resource_type)
        if resource:
            f[resource] += 1.0
    return f


def to_vector(features: dict[str, Any]) -> list[float]:
    """Fixed-order vector; a missing or non-numeric value becomes 0.0 (never an exception)."""
    out = []
    for name in FEATURE_NAMES:
        value = features.get(name, 0.0)
        try:
            number = float(value)
        except (TypeError, ValueError):
            number = 0.0
        out.append(number if number == number and abs(number) != float("inf") else 0.0)  # NaN / inf -> 0
    return out
