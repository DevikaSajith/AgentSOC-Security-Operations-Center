"""Simulator-generated training data (TRAINING TIME ONLY: the prediction path never imports this module).

    scenario / behaviour  ->  events (existing simulator)  ->  Monitor correlation + enrichment
      ->  deterministic features  ->  (features, label, time)

The LABEL is the behaviour that generated the events (BENIGN, or the attack scenario). It is never produced by
an LLM. Noise (benign look-alikes, truncated attacks, attacker reconnaissance mixed in) keeps the problem
from being trivially separable; the data is still synthetic and the report says so. Timestamps are
synthetic, strictly increasing per sample, so a chronological train/test split is meaningful and
deterministic for a given seed.
"""

import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from app.agents.monitor.config import MonitorConfig
from app.agents.monitor.correlation import correlate
from app.agents.monitor.enrichment import Enricher
from app.agents.monitor.models import NormalizedEvent
from app.domain.events import SecurityEvent
from app.ml.config import MLConfig
from app.ml.features import extract_features
from app.simulator.attacks import AttackSimulator
from app.simulator.cloud import CloudSimulator, ResourceNotFoundError
from app.simulator.events import INSTANCES, KNOWN_USER_IPS, EventGenerator

BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
SPACING = timedelta(minutes=10)

SCENARIO_FOR_LABEL = {
    "IAM_PRIVILEGE_ESCALATION": "iam_privilege_escalation",
    "CREDENTIAL_MISUSE": "credential_misuse",
    "S3_UNAUTHORIZED_ACCESS": "public_s3_exposure",
    "EC2_COMPROMISE": "ec2_compromise",
}
RECON_TYPES = ["ListBuckets", "GetCallerIdentity", "DescribeInstances", "ListUsers"]


@dataclass(frozen=True)
class Sample:
    features: dict[str, float]
    label: str
    time: datetime
    source: str = "simulator"  # simulator | learning_record


def _lookup(cloud: CloudSimulator):  # type: ignore[no-untyped-def]
    def lookup(resource_type: str, resource_id: str) -> dict[str, Any] | None:
        getter = {"IAMUser": cloud.get_user, "EC2Instance": cloud.get_instance, "S3Bucket": cloud.get_bucket}.get(resource_type)
        try:
            return getter(resource_id).model_dump(mode="json") if getter else None
        except ResourceNotFoundError:
            return None
    return lookup


def _benign(gen: EventGenerator, rng: random.Random, clock_time: datetime, noise: bool) -> list[SecurityEvent]:
    user = rng.choice(list(KNOWN_USER_IPS))
    count = rng.randint(1, 6)
    stamps = sorted(clock_time - timedelta(seconds=rng.uniform(0, 25 * 60)) for _ in range(count))
    events = [gen.normal_event(user, timestamp=t) for t in stamps]
    if noise and rng.random() < 0.25:  # a benign look-alike: an employee logging in from a new place
        events[-1] = gen.create_event("Login", user=user, source_ip=gen.suspicious_ip(), timestamp=stamps[-1],
                                      details={"anomaly": "unusual_source_ip"})
    if noise and rng.random() < 0.10:  # routine admin work from the trusted network
        events.append(gen.create_event("CreateAccessKey", user=user, source_ip=KNOWN_USER_IPS[user],
                                       timestamp=stamps[-1] + timedelta(seconds=30)))
    return events


def _network(gen: EventGenerator, rng: random.Random, clock_time: datetime) -> list[SecurityEvent]:
    user, instance = rng.choice(list(KNOWN_USER_IPS)), rng.choice(INSTANCES)
    ip = gen.suspicious_ip() if rng.random() < 0.6 else KNOWN_USER_IPS[user]
    count = rng.randint(2, 4)
    stamps = sorted(clock_time - timedelta(seconds=rng.uniform(0, 8 * 60)) for _ in range(count))
    return [gen.create_event("NetworkFlowAnomaly", user=user, source_ip=ip, resource_id=instance, timestamp=t,
                             details={"direction": "outbound", "destination_ip": "198.51.100.200",
                                      "destination_port": rng.choice([4444, 8080, 9001]),
                                      "bytes_out": rng.randint(100_000_000, 900_000_000)}) for t in stamps]


def _attack(label: str, cloud: CloudSimulator, gen: EventGenerator, rng: random.Random, clock: Any,
            noise: bool) -> list[SecurityEvent]:
    events = list(AttackSimulator(cloud, gen, rng, clock).run(SCENARIO_FOR_LABEL[label]).events)
    if noise and rng.random() < 0.25:  # caught EARLY: only the first 1-2 events exist, so classes genuinely overlap
        events = events[: rng.randint(1, 2)]
    elif noise and len(events) > 2 and rng.random() < 0.35:  # a truncated attack (the detector saw only part of it)
        events.pop(rng.randrange(len(events)))
    if noise and rng.random() < 0.40:  # the attacker's reconnaissance mixed in
        last = events[-1]
        for k in range(rng.randint(1, 2)):
            events.append(gen.create_event(rng.choice(RECON_TYPES), user=last.user, source_ip=last.source_ip,
                                           timestamp=last.timestamp + timedelta(seconds=rng.randint(5, 60) * (k + 1))))
    return events


def generate_dataset(config: MLConfig, monitor: MonitorConfig, *, seed: int | None = None,
                     samples_per_class: int | None = None) -> list[Sample]:
    """Deterministic for a given (config, seed). Returned in chronological order."""
    seed = config.dataset.seed if seed is None else seed
    per_class = samples_per_class or config.dataset.samples_per_class
    rng = random.Random(seed)
    labels = [label for label in config.model.labels for _ in range(per_class)]
    rng.shuffle(labels)
    samples: list[Sample] = []
    for index, label in enumerate(labels):
        when = BASE_TIME + SPACING * index
        cloud, clock = CloudSimulator(), (lambda w=when: w)
        gen = EventGenerator(rng=rng, clock=clock)
        if label == config.model.benign_label:
            events = _benign(gen, rng, when, config.dataset.noise)
        elif label == "SUSPICIOUS_NETWORK_ACTIVITY":
            events = _network(gen, rng, when)
        else:
            events = _attack(label, cloud, gen, rng, clock, config.dataset.noise)
        items = [NormalizedEvent(event=e, fingerprint=uuid.UUID(int=rng.getrandbits(128)).hex, ingest_format="security_event",
                                 stored=True) for e in events]
        enricher = Enricher(monitor, _lookup(cloud))
        groups = [enricher.build_group(g) for g in correlate(items, monitor.correlation.window_seconds)]
        group = max(groups, key=lambda g: len(g.events))  # the Monitor scores each group; the attack is the biggest
        samples.append(Sample(features=extract_features(group), label=label, time=when))
    return sorted(samples, key=lambda s: s.time)
