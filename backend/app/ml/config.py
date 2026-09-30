"""Typed loader for config/ml_config.yaml (labels, model + dataset parameters, risk thresholds, storage)."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.config import BACKEND_DIR

ML_CONFIG_FILE = "ml_config.yaml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ModelParams(_Strict):
    feature_version: str
    benign_label: str
    labels: tuple[str, ...]
    n_estimators: int = Field(ge=10, le=2000)
    max_depth: int | None = Field(default=None, ge=1)
    min_samples_leaf: int = Field(ge=1)
    random_state: int


class DatasetParams(_Strict):
    samples_per_class: int = Field(ge=10, le=20000)
    test_fraction: float = Field(gt=0.0, lt=0.9)
    seed: int
    noise: bool


class RiskThresholds(_Strict):
    medium: float = Field(gt=0.0, lt=1.0)
    high: float = Field(gt=0.0, lt=1.0)


class MonitorParams(_Strict):
    signal_probability: float = Field(gt=0.0, le=1.0)


class ExplainParams(_Strict):
    top_features: int = Field(ge=1, le=20)


class StorageParams(_Strict):
    model_dir: str


class MLConfig(_Strict):
    model: ModelParams
    dataset: DatasetParams
    risk: RiskThresholds
    monitor: MonitorParams
    explain: ExplainParams
    storage: StorageParams

    @model_validator(mode="after")
    def _consistent(self) -> "MLConfig":
        if self.model.benign_label not in self.model.labels:
            raise ValueError("benign_label must be one of the labels")
        if not self.risk.medium < self.risk.high:
            raise ValueError("risk.medium must be below risk.high")
        if len(set(self.model.labels)) != len(self.model.labels) or len(self.model.labels) < 2:
            raise ValueError("labels must be at least two distinct names")
        return self

    def risk_level(self, probability: float) -> str:
        if probability >= self.risk.high:
            return "high"
        return "medium" if probability >= self.risk.medium else "low"

    def model_dir(self) -> Path:
        path = Path(self.storage.model_dir)
        return path if path.is_absolute() else BACKEND_DIR / path


class MLConfigError(RuntimeError):
    """ml_config.yaml is missing or invalid."""


def load_ml_config(config_dir: Path) -> MLConfig:
    path = config_dir / ML_CONFIG_FILE
    if not path.is_file():
        raise MLConfigError(f"{ML_CONFIG_FILE} not found in {config_dir}")
    try:
        return MLConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, ValueError) as exc:
        raise MLConfigError(f"invalid {ML_CONFIG_FILE}: {exc}") from exc
