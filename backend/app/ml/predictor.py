"""Prediction: READ -> FEATURES -> PREDICTION. This module has no ToolExecutor, no simulator, no approvals, no
network and no shell: it turns an event group (or a feature dict) into an MLPrediction and nothing else.
"""

import threading
from typing import Any

from app.agents.monitor.models import EventGroup
from app.domain.ml import ImportantFeature, MLPrediction
from app.ml.config import MLConfig
from app.ml.features import FEATURE_NAMES, FEATURES, FeatureError, extract_features, to_vector
from app.ml.store import ModelStore, ModelStoreError


class ModelUnavailableError(RuntimeError):
    """There is no active model (or it cannot be loaded). Prediction is unavailable; nothing else is affected."""


class ThreatPredictor:
    def __init__(self, store: ModelStore, config: MLConfig) -> None:
        self._store = store
        self._config = config
        self._lock = threading.Lock()
        self._loaded: tuple[str, Any, dict[str, Any]] | None = None

    # ---------------------------------------------------------------- model
    def _model(self) -> tuple[str, Any, dict[str, Any]]:
        version = self._store.active_version()
        if version is None:
            raise ModelUnavailableError("no active ML model; train one explicitly (POST /api/ml/train)")
        with self._lock:
            if self._loaded is None or self._loaded[0] != version:
                try:
                    model, meta = self._store.load(version)
                except (ModelStoreError, OSError, ValueError) as exc:
                    self._loaded = None
                    raise ModelUnavailableError(f"active ML model '{version}' cannot be loaded: {exc}") from exc
                if meta.get("feature_version") != self._config.model.feature_version or list(meta.get("feature_names", [])) != list(FEATURE_NAMES):
                    raise ModelUnavailableError(f"model '{version}' was trained with a different feature set; retrain it")
                self._loaded = (version, model, meta)
            return self._loaded

    def status(self) -> dict[str, Any]:
        """Never raises: reports availability, the active version and any load problem."""
        active = self._store.active_version()
        info: dict[str, Any] = {"engine": "ML Prediction Engine", "kind": "Random Forest (decision support)", "autonomous_agent": False,
                                "available": False, "active_version": active, "versions": len(self._store.versions()),
                                "feature_version": self._config.model.feature_version, "error": None}
        try:
            version, _, meta = self._model()
        except ModelUnavailableError as exc:
            info["error"] = str(exc)
            return info
        info.update(available=True, active_version=version, training_timestamp=meta.get("training_timestamp"),
                    dataset_size=meta.get("dataset_size"), classes=meta.get("classes"), data_source=meta.get("data_source"))
        return info

    # ------------------------------------------------------------ prediction
    def predict_group(self, group: EventGroup) -> MLPrediction:
        try:
            features = extract_features(group)
        except FeatureError as exc:
            raise ValueError(str(exc)) from None
        return self.predict_features(features)

    def predict_features(self, features: dict[str, Any]) -> MLPrediction:
        version, model, meta = self._model()
        vector = to_vector(features)
        probabilities = model.predict_proba([vector])[0]
        classes = [str(c) for c in model.classes_]
        by_class = {c: round(float(p), 4) for c, p in zip(classes, probabilities)}
        benign = self._config.model.benign_label
        best = max(by_class, key=lambda c: by_class[c])
        threat = round(1.0 - by_class.get(benign, 0.0), 4)
        importances = dict(zip(meta["feature_names"], (float(x) for x in model.feature_importances_)))
        active = [(n, v) for n, v in zip(FEATURE_NAMES, vector) if v != 0.0]
        ranked = sorted(active, key=lambda nv: -importances.get(nv[0], 0.0))[: self._config.explain.top_features]
        return MLPrediction(
            prediction=best, threat_probability=threat, prediction_probability=by_class[best],
            risk_level=self._config.risk_level(threat), is_threat=best != benign and threat >= self._config.monitor.signal_probability,
            model_version=version, feature_version=meta["feature_version"], class_probabilities=by_class,
            important_features=[ImportantFeature(name=n, value=round(v, 3), importance=round(min(1.0, importances.get(n, 0.0)), 4),
                                                 description=FEATURES[n]) for n, v in ranked],
            features={n: round(v, 4) for n, v in zip(FEATURE_NAMES, vector)})
