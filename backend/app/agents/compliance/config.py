"""Typed loaders for config/compliance_mapping.yaml (what may be claimed) and
config/compliance_policy.yaml (how strictly it is validated). Cross-references are checked at load
time: a rule or control pointing at something undefined makes the file invalid."""

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.compliance import DataClassification, RecommendationType
from app.domain.enums import Severity

MAPPING_FILE = "compliance_mapping.yaml"
POLICY_FILE = "compliance_policy.yaml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# ----------------------------------------------------------------------------- mapping
class Framework(_Strict):
    name: str
    version: str


class FrameworkControl(_Strict):
    id: str = Field(min_length=1, max_length=30)
    title: str


class Triggers(_Strict):
    event_types: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    resource_types: tuple[str, ...] = ()
    always: bool = False


class Control(_Strict):
    name: str
    description: str
    triggers: Triggers
    frameworks: dict[str, tuple[FrameworkControl, ...]]


class AssetMetadata(_Strict):
    classification: DataClassification
    environment: str | None = None
    basis: str


class ViolationRule(_Strict):
    id: str
    control: str
    description: str
    requires_event_types: tuple[str, ...]
    requires_indicators: tuple[str, ...] = ()


class ReportingRule(_Strict):
    id: str
    description: str
    min_severity: Severity
    controls_any: tuple[str, ...] = ()
    data_classifications_any: tuple[DataClassification, ...] = ()
    requirement: str


class ComplianceMapping(_Strict):
    frameworks: dict[str, Framework]
    controls: dict[str, Control]
    asset_metadata: dict[str, AssetMetadata] = {}
    violation_rules: tuple[ViolationRule, ...] = ()
    reporting_rules: tuple[ReportingRule, ...] = ()

    @model_validator(mode="after")
    def _cross_references(self) -> "ComplianceMapping":
        for control_id, control in self.controls.items():
            unknown = set(control.frameworks) - set(self.frameworks)
            if unknown:
                raise ValueError(f"control '{control_id}' maps to undefined frameworks {sorted(unknown)}")
        for rule in self.violation_rules:
            if rule.control not in self.controls:
                raise ValueError(f"violation rule {rule.id} references undefined control '{rule.control}'")
        for rule in self.reporting_rules:
            missing = set(rule.controls_any) - set(self.controls)
            if missing:
                raise ValueError(f"reporting rule {rule.id} references undefined controls {sorted(missing)}")
        ids = [r.id for r in (*self.violation_rules, *self.reporting_rules)]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        return self

    def framework_control(self, control_id: str, framework: str, framework_control_id: str) -> FrameworkControl | None:
        for item in self.controls.get(control_id, Control.model_construct(frameworks={})).frameworks.get(framework, ()):
            if item.id == framework_control_id:
                return item
        return None


# ------------------------------------------------------------------------------ policy
class ContextRules(_Strict):
    max_evidence_items: int = Field(ge=5, le=200)
    max_string_length: int = Field(ge=40, le=2000)
    max_context_chars: int = Field(ge=2000, le=100_000)


class PolicyRules(_Strict):
    max_repair_attempts: int = Field(ge=0, le=3)
    min_evidence_for_assessment: int = Field(ge=1)
    min_observed_for_adverse_status: int = Field(ge=1)
    violation_requires_matched_rule: bool
    forbidden_text_patterns: tuple[str, ...]
    recommendation_forbidden_patterns: tuple[str, ...]
    recommendation_types: tuple[RecommendationType, ...]

    @model_validator(mode="after")
    def _patterns_compile(self) -> "PolicyRules":
        for pattern in (*self.forbidden_text_patterns, *self.recommendation_forbidden_patterns):
            re.compile(pattern)
        return self


class FallbackRules(_Strict):
    confidence: float = Field(ge=0.0, le=1.0)
    control_confidence: float = Field(ge=0.0, le=1.0)


class ComplianceConfig(_Strict):
    context: ContextRules
    policy: PolicyRules
    fallback: FallbackRules
    standing_unknowns: dict[str, str]


class ComplianceConfigError(RuntimeError):
    """A compliance configuration file is missing or invalid."""


class ComplianceSettings(_Strict):
    """Everything the Compliance Agent is configured with."""

    mapping: ComplianceMapping
    config: ComplianceConfig


def _load(path: Path, model):  # type: ignore[no-untyped-def]
    if not path.is_file():
        raise ComplianceConfigError(f"{path.name} not found in {path.parent}")
    try:
        return model.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, ValueError) as exc:
        raise ComplianceConfigError(f"invalid {path.name}: {exc}") from exc


def load_compliance_settings(config_dir: Path) -> ComplianceSettings:
    return ComplianceSettings(mapping=_load(config_dir / MAPPING_FILE, ComplianceMapping),
                              config=_load(config_dir / POLICY_FILE, ComplianceConfig))
