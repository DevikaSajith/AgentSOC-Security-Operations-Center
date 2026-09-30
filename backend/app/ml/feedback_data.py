"""Turns Phase 8 learning records into extra TRAINING samples (explicit training only, never automatic).

A record contributes only when a human explicitly marked the response `correct` (a verified-by-a-person outcome)
and the incident kept the numeric ML features that were used at prediction time; its label is the class the
model predicted for that incident. Everything else is skipped and counted, so the report can say how much of the
feedback was usable. No identities, prompts or secrets are involved: features are counts and flags.
"""

from app.domain.learning import FeedbackType, HumanFeedback, LearningRecord
from app.ml.config import MLConfig
from app.ml.dataset import Sample


def samples_from_learning(records: list[LearningRecord], config: MLConfig) -> tuple[list[Sample], dict[str, int]]:
    samples: list[Sample] = []
    skipped = {"no_ml_features": 0, "no_human_confirmation": 0, "unknown_label": 0, "retry_or_regression": 0}
    for r in records:
        if r.feedback_type in (FeedbackType.RETRY_REQUESTED, FeedbackType.REGRESSION_DETECTED):
            skipped["retry_or_regression"] += 1
        elif not r.ml_features or not r.ml_prediction:
            skipped["no_ml_features"] += 1
        elif r.human_feedback != HumanFeedback.CORRECT:
            skipped["no_human_confirmation"] += 1
        elif r.ml_prediction not in config.model.labels:
            skipped["unknown_label"] += 1
        else:
            samples.append(Sample(features=dict(r.ml_features), label=r.ml_prediction, time=r.timestamp, source="learning_record"))
    return samples, skipped
