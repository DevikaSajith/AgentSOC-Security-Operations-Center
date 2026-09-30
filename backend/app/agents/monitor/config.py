"""Typed loader for config/monitor_rules.yaml (the single home of every Monitor threshold)."""

import ipaddress
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.enums import IncidentCategory, Priority, Severity

MONITOR_RULES_FILE = "monitor_rules.yaml"

INDICATORS = ("high_severity", "suspicious_event_type", "untrusted_source_ip",
              "sensitive_resource", "principal_ip_change", "privileged_principal",
              "correlated_group", "ml_threat_predicted")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ValidationRules(_Strict):
    max_future_skew_seconds: int = Field(ge=0)
    max_event_age_days: int = Field(ge=1)


class CorrelationRules(_Strict):
    window_seconds: int = Field(ge=1)


class CorrelatedGroupRule(_Strict):
    min_events: int = Field(ge=2)
    min_distinct_indicators: int = Field(ge=1)


class CreateWhen(_Strict):
    min_event_severity: Severity
    any_suspicious_event_type: bool
    correlated_group: CorrelatedGroupRule


class IncidentRules(_Strict):
    merge_window_minutes: int = Field(ge=0)
    closed_statuses: tuple[str, ...]
    create_when: CreateWhen
    severity_floor: Severity


class ConfidenceRules(_Strict):
    indicator_weights: dict[str, float]
    max_confidence: float = Field(gt=0.0, le=1.0)

    @field_validator("indicator_weights")
    @classmethod
    def _known_indicators(cls, value: dict[str, float]) -> dict[str, float]:
        unknown = set(value) - set(INDICATORS)
        if unknown:
            raise ValueError(f"unknown indicators: {sorted(unknown)}")
        if any(not 0.0 <= w < 1.0 for w in value.values()):
            raise ValueError("indicator weights must be in [0, 1)")
        return value


class MonitorConfig(_Strict):
    validation: ValidationRules
    trusted_networks: tuple[str, ...]
    sensitive_resources: frozenset[str]
    suspicious_event_types: frozenset[str]
    default_severity_by_event_type: dict[str, Severity]
    category_by_event_type: dict[str, IncidentCategory]
    category_by_resource_type: dict[str, IncidentCategory]
    correlation: CorrelationRules
    incident: IncidentRules
    confidence: ConfidenceRules
    priority_by_severity: dict[Severity, Priority]

    @field_validator("trusted_networks")
    @classmethod
    def _valid_networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for network in value:
            ipaddress.ip_network(network)  # raises ValueError on bad CIDR
        return value

    @field_validator("priority_by_severity")
    @classmethod
    def _every_severity_mapped(cls, value: dict[Severity, Priority]) -> dict[Severity, Priority]:
        missing = set(Severity) - set(value)
        if missing:
            raise ValueError(f"priority missing for: {sorted(s.value for s in missing)}")
        return value

    def networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(n) for n in self.trusted_networks]


class MonitorConfigError(RuntimeError):
    """monitor_rules.yaml is missing or invalid."""


def load_monitor_config(config_dir: Path) -> MonitorConfig:
    path = config_dir / MONITOR_RULES_FILE
    if not path.is_file():
        raise MonitorConfigError(f"{MONITOR_RULES_FILE} not found in {config_dir}")
    try:
        return MonitorConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, ValueError) as exc:
        raise MonitorConfigError(f"invalid {MONITOR_RULES_FILE}: {exc}") from exc
