"""Attack scenarios: each one emits a correlated event sequence AND changes cloud state."""

import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel

from app.domain.incident import AffectedResource
from app.simulator.cloud import CloudSimulator
from app.simulator.events import KNOWN_USER_IPS, EventGenerator, SecurityEvent
from app.simulator.resources import ActionResult, utcnow

logger = logging.getLogger(__name__)

EVENTS_PER_SCENARIO = 4


class UnknownScenarioError(ValueError):
    """Raised when a scenario name is not registered."""


class ScenarioResult(BaseModel):
    """Everything a scenario run produced."""

    scenario_id: str
    scenario_name: str
    description: str
    events: list[SecurityEvent]
    affected_resources: list[AffectedResource]
    attack_start_time: datetime
    attack_end_time: datetime
    state_changes: list[ActionResult]
    cloud_state_changed: bool


@dataclass
class _Run:
    """Mutable scratchpad for one scenario run."""

    scenario_id: str
    generator: EventGenerator
    timestamps: list[datetime]
    events: list[SecurityEvent] = field(default_factory=list)
    changes: list[ActionResult] = field(default_factory=list)
    affected: dict[tuple[str, str], AffectedResource] = field(default_factory=dict)

    def emit(self, event_type: str, *, user: str, source_ip: str,
             resource_id: str | None = None, details: dict[str, Any] | None = None) -> SecurityEvent:
        """Create the next event in the sequence, tagged with the scenario ID."""
        step = len(self.events) + 1
        event = self.generator.create_event(
            event_type, user=user, source_ip=source_ip, resource_id=resource_id,
            timestamp=self.timestamps[step - 1],
            details={**(details or {}), "scenario_id": self.scenario_id, "step": step},
        )
        self.events.append(event)
        self.affect(event.resource_type, event.resource_id)
        return event

    def change(self, result: ActionResult) -> dict[str, Any]:
        """Record a cloud state change; returns a dict to embed in event details."""
        self.changes.append(result)
        self.affect(result.resource_type, result.resource)
        return {"state_change": {"action": result.action, "old_state": result.old_state,
                                 "new_state": result.new_state}}

    def affect(self, resource_type: str, resource_id: str) -> None:
        """Mark a resource as affected (ignores wildcard listings)."""
        if resource_id != "*":
            self.affected[(resource_type, resource_id)] = AffectedResource(
                resource_type=resource_type, resource_id=resource_id)


@dataclass(frozen=True)
class _Scenario:
    description: str
    runner: Callable[["AttackSimulator", _Run], None]


class AttackSimulator:
    """Runs attack scenarios against a CloudSimulator."""

    def __init__(
        self,
        cloud: CloudSimulator,
        generator: EventGenerator | None = None,
        rng: random.Random | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.cloud = cloud
        self._rng = rng or random.Random()
        self._clock = clock
        self.generator = generator or EventGenerator(rng=self._rng, clock=clock)
        self._scenarios: dict[str, _Scenario] = {
            "iam_privilege_escalation": _Scenario(
                "Attacker logs in with alice's stolen credentials, creates a new access "
                "key, grants alice admin rights and reads a secret.",
                AttackSimulator._iam_privilege_escalation),
            "public_s3_exposure": _Scenario(
                "Attacker logs in as bob, makes the private 'company-data' bucket public "
                "and downloads a sensitive object.",
                AttackSimulator._public_s3_exposure),
            "ec2_compromise": _Scenario(
                "Attacker logs in as bob, runs commands on ec2-001, escalates through the "
                "instance role and starts abnormal outbound network traffic.",
                AttackSimulator._ec2_compromise),
            "credential_misuse": _Scenario(
                "Alice's credentials are used from her normal IP, then from a suspicious "
                "IP that lists and reads sensitive resources.",
                AttackSimulator._credential_misuse),
        }

    def list_scenarios(self) -> list[dict[str, str]]:
        """Names and descriptions of the available scenarios."""
        return [{"name": n, "description": s.description} for n, s in self._scenarios.items()]

    def run(self, name: str) -> ScenarioResult:
        """Run one scenario. The caller decides whether to reset the cloud first."""
        scenario = self._scenarios.get(name)
        if scenario is None:
            raise UnknownScenarioError(
                f"unknown scenario '{name}'. Valid: {', '.join(self._scenarios)}")
        scenario_id = str(uuid4())
        logger.info("simulation started: %s (%s)", name, scenario_id)
        before = self.cloud.get_cloud_state()
        run = _Run(scenario_id, self.generator, self._timestamps(EVENTS_PER_SCENARIO))
        scenario.runner(self, run)
        result = ScenarioResult(
            scenario_id=scenario_id,
            scenario_name=name,
            description=scenario.description,
            events=run.events,
            affected_resources=list(run.affected.values()),
            attack_start_time=run.events[0].timestamp,
            attack_end_time=run.events[-1].timestamp,
            state_changes=run.changes,
            cloud_state_changed=before != self.cloud.get_cloud_state(),
        )
        logger.info("simulation completed: %s, %d events", name, len(run.events))
        return result

    # ------------------------------------------------------------- scenarios
    def _iam_privilege_escalation(self, run: _Run) -> None:
        user, ip = "alice", self.generator.suspicious_ip()
        run.emit("Login", user=user, source_ip=ip,
                 details={"anomaly": "unusual_source_ip", "mfa_used": False})
        key = self.cloud.create_access_key(user)
        run.emit("CreateAccessKey", user=user, source_ip=ip,
                 details={"access_key_id": key.new_state["newest_key_id"], **run.change(key)})
        admin = self.cloud.make_user_admin(user)
        run.emit("AttachAdminPolicy", user=user, source_ip=ip, details=run.change(admin))
        run.emit("GetSecretValue", user=user, source_ip=ip)

    def _public_s3_exposure(self, run: _Run) -> None:
        user, ip, bucket = "bob", self.generator.suspicious_ip(), "company-data"
        run.emit("Login", user=user, source_ip=ip, details={"anomaly": "unusual_source_ip"})
        run.emit("PutBucketPolicy", user=user, source_ip=ip, resource_id=bucket)
        public = self.cloud.make_bucket_public(bucket)
        run.emit("DeletePublicAccessBlock", user=user, source_ip=ip, resource_id=bucket,
                 details=run.change(public))
        run.emit("GetObject", user=user, source_ip=ip, resource_id=bucket,
                 details={"key": "customers/pii-export.csv", "sensitive": True})

    def _ec2_compromise(self, run: _Run) -> None:
        user, ip, instance = "bob", self.generator.suspicious_ip(), "ec2-001"
        run.emit("Login", user=user, source_ip=ip, details={"anomaly": "unusual_source_ip"})
        run.emit("ExecuteCommand", user=user, source_ip=ip, resource_id=instance,
                 details={"command": "whoami; uname -a; simulated-stage2-download"})
        role = self.cloud.set_instance_role(instance, "ec2-admin-role")
        run.emit("AssumeRole", user=user, source_ip=ip, resource_id=instance,
                 details=run.change(role))
        run.emit("NetworkFlowAnomaly", user=user, source_ip=ip, resource_id=instance,
                 details={"direction": "outbound", "destination_ip": "198.51.100.200",
                          "destination_port": 4444, "bytes_out": 734003200})

    def _credential_misuse(self, run: _Run) -> None:
        user, bad_ip = "alice", self.generator.suspicious_ip()
        run.emit("Login", user=user, source_ip=KNOWN_USER_IPS[user])
        used = self.cloud.record_access_key_use(user, bad_ip)
        run.emit("Login", user=user, source_ip=bad_ip,
                 details={"anomaly": "unusual_source_ip", **run.change(used)})
        run.emit("ListBuckets", user=user, source_ip=bad_ip, details={"sensitive_listing": True})
        run.emit("GetObject", user=user, source_ip=bad_ip, resource_id="company-data",
                 details={"key": "finance/payroll-2026.xlsx", "sensitive": True})

    # --------------------------------------------------------------- helpers
    def _timestamps(self, count: int) -> list[datetime]:
        """Increasing timestamps (5-45 s apart) so the attack ends 'now'."""
        gaps = [self._rng.uniform(5, 45) for _ in range(count - 1)]
        start = self._clock() - timedelta(seconds=sum(gaps))
        stamps, current = [start], start
        for gap in gaps:
            current += timedelta(seconds=gap)
            stamps.append(current)
        return stamps
