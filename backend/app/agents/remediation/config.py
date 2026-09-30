"""Typed loader for config/remediation_policy.yaml. Every action in the policy must be an action tool that
exists in the tool layer; anything else makes the file invalid (the API then reports 503)."""

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.enums import Severity
from app.tools.registry import ACTION_TOOL_NAMES

POLICY_FILE = "remediation_policy.yaml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ContextRules(_Strict):
    max_evidence_items: int = Field(ge=5, le=200)
    max_string_length: int = Field(ge=40, le=2000)
    max_context_chars: int = Field(ge=2000, le=100_000)


class ApprovalRules(_Strict):
    ttl_minutes: int = Field(ge=1, le=10_080)


class PolicyRules(_Strict):
    max_repair_attempts: int = Field(ge=0, le=3)
    min_evidence_for_action: int = Field(ge=1)
    min_observed_for_action: int = Field(ge=1)
    forbidden_text_patterns: tuple[str, ...]
    fallback_priority: tuple[str, ...]
    fallback_confidence: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _patterns_compile(self) -> "PolicyRules":
        for pattern in self.forbidden_text_patterns:
            re.compile(pattern)
        return self


class ActionPolicy(_Strict):
    enabled: bool
    risk: Severity
    requires_approval: bool
    resource_type: str
    argument: str
    requires_state: dict[str, Any]
    postcondition: dict[str, Any]
    fingerprint_fields: tuple[str, ...]
    relevant_event_types: tuple[str, ...] = ()
    requires_indicators_any: tuple[str, ...] = ()
    description: str
    rollback_available: bool
    rollback_description: str


class RemediationPolicy(_Strict):
    context: ContextRules
    approval: ApprovalRules
    policy: PolicyRules
    protected_resources: dict[str, str] = {}
    actions: dict[str, ActionPolicy]

    @model_validator(mode="after")
    def _known_actions(self) -> "RemediationPolicy":
        unknown = set(self.actions) - ACTION_TOOL_NAMES
        if unknown:
            raise ValueError(f"policy defines actions that are not registered action tools: {sorted(unknown)}")
        missing = set(self.policy.fallback_priority) - set(self.actions)
        if missing:
            raise ValueError(f"fallback_priority names undefined actions: {sorted(missing)}")
        for name, action in self.actions.items():
            if not action.requires_approval:
                raise ValueError(f"action '{name}' must require human approval")
        return self


class RemediationConfigError(RuntimeError):
    """The remediation policy file is missing or invalid."""


RemediationSettings = RemediationPolicy


def load_remediation_settings(config_dir: Path) -> RemediationPolicy:
    path = config_dir / POLICY_FILE
    if not path.is_file():
        raise RemediationConfigError(f"{path.name} not found in {path.parent}")
    try:
        return RemediationPolicy.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, ValueError) as exc:
        raise RemediationConfigError(f"invalid {path.name}: {exc}") from exc
