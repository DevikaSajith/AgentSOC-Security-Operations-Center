"""Typed loader for config/verification_rules.yaml. Every registered action tool must have a rule and no rule
may name anything else, so no remediation action can be left unverifiable or invented."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.tools.registry import ACTION_TOOL_NAMES

RULES_FILE = "verification_rules.yaml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Confidence(_Strict):
    verified: float = Field(ge=0.0, le=1.0)
    failed: float = Field(ge=0.0, le=1.0)
    partial: float = Field(ge=0.0, le=1.0)
    unknown: float = Field(ge=0.0, le=1.0)
    execution_failed: float = Field(ge=0.0, le=1.0)


class ActionRule(_Strict):
    resource_type: str
    description: str
    required_state: dict[str, Any]

    @model_validator(mode="after")
    def _not_empty(self) -> "ActionRule":
        if not self.required_state:
            raise ValueError("required_state must name at least one field")
        return self


class VerificationRules(_Strict):
    confidence: Confidence
    verification: dict[str, ActionRule]

    @model_validator(mode="after")
    def _covers_exactly_the_action_tools(self) -> "VerificationRules":
        if set(self.verification) != set(ACTION_TOOL_NAMES):
            missing = sorted(set(ACTION_TOOL_NAMES) - set(self.verification))
            extra = sorted(set(self.verification) - set(ACTION_TOOL_NAMES))
            raise ValueError(f"rules must cover exactly the registered action tools (missing {missing}, unknown {extra})")
        return self


class VerificationConfigError(RuntimeError):
    """The verification rules file is missing or invalid."""


def load_verification_rules(config_dir: Path) -> VerificationRules:
    path = config_dir / RULES_FILE
    if not path.is_file():
        raise VerificationConfigError(f"{path.name} not found in {path.parent}")
    try:
        return VerificationRules.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, ValueError) as exc:
        raise VerificationConfigError(f"invalid {path.name}: {exc}") from exc
