"""Typed loader for config/feedback_rules.yaml (retry limit, verification->feedback map, recommendation ladder)."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.learning import FailureReason, FeedbackType, Recommendation

RULES_FILE = "feedback_rules.yaml"
VERIFICATION_STATUSES = ("verified", "failed", "partial", "unknown")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Ladder(_Strict):
    with_retries_left: Recommendation
    when_exhausted: Recommendation


class FeedbackRules(_Strict):
    retry_limit: int = Field(ge=0, le=10)
    feedback_by_verification: dict[str, FeedbackType]
    recommendations: dict[FailureReason, Ladder]
    partial_response: Ladder
    successful_response: Recommendation
    regression_detected: Ladder

    @model_validator(mode="after")
    def _complete(self) -> "FeedbackRules":
        if set(self.feedback_by_verification) != set(VERIFICATION_STATUSES):
            raise ValueError(f"feedback_by_verification must map exactly {VERIFICATION_STATUSES}")
        missing = set(FailureReason) - set(self.recommendations)
        if missing:
            raise ValueError(f"recommendations missing for {sorted(m.value for m in missing)}")
        return self

    def recommend(self, ladder: Ladder, retry_count: int) -> Recommendation:
        return ladder.with_retries_left if retry_count < self.retry_limit else ladder.when_exhausted


class FeedbackConfigError(RuntimeError):
    """The feedback rules file is missing or invalid."""


def load_feedback_rules(config_dir: Path) -> FeedbackRules:
    path = config_dir / RULES_FILE
    if not path.is_file():
        raise FeedbackConfigError(f"{path.name} not found in {path.parent}")
    try:
        return FeedbackRules.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, ValueError) as exc:
        raise FeedbackConfigError(f"invalid {path.name}: {exc}") from exc
