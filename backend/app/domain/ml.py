"""ML threat-prediction result (Phase 9). Decision SUPPORT only.

An MLPrediction is a probability estimated by a Random Forest trained on simulator-generated data. It is NOT a
confirmed attack and NOT the incident's confidence (which the Monitor / Triage / other agents compute
separately). The ML layer has no tool access: READ (events) -> FEATURES -> PREDICTION.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.domain.enums import Severity  # noqa: F401  (risk levels reuse the project's low/medium/high wording)

RISK_LEVELS = ("low", "medium", "high")

ML_NOTE = ("ML prediction (decision support): a model estimate from simulator-generated training data, not a "
           "confirmed attack and not the incident confidence.")


class ImportantFeature(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    value: float
    importance: float = Field(ge=0.0, le=1.0)  # the model's GLOBAL importance of this feature
    description: str


class MLPrediction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prediction: str  # e.g. IAM_PRIVILEGE_ESCALATION or BENIGN
    threat_probability: float = Field(ge=0.0, le=1.0)  # P(activity is a threat) = 1 - P(BENIGN)
    prediction_probability: float = Field(ge=0.0, le=1.0)  # P(the predicted class)
    risk_level: str  # low | medium | high, from config/ml_config.yaml thresholds
    is_threat: bool  # prediction != BENIGN and threat_probability >= the configured signal threshold
    model_version: str
    model_type: str = "RandomForestClassifier"
    feature_version: str
    important_features: list[ImportantFeature]
    class_probabilities: dict[str, float]
    features: dict[str, float]  # the numeric features used (no identities, IPs or secrets)
    note: str = ML_NOTE
    data_source: str = "simulator-generated"
