"""/api/ml/*: the ML Threat Predictor (a prediction engine, NOT an agent).

Prediction is READ -> FEATURES -> PREDICTION: these endpoints never touch the ToolExecutor, the cloud, approvals
or incidents. Training is explicit (POST /api/ml/train) and never changes the active model unless asked to; the
active model is switched only by an explicit activate call.
"""

import threading
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, model_validator

from app.agents.monitor.correlation import correlate
from app.agents.monitor.enrichment import Enricher
from app.agents.monitor.models import NormalizedEvent
from app.api.deps import ready_database, record_audit
from app.domain.enums import HumanActor
from app.domain.events import SecurityEvent
from app.domain.incident import AuditEntry
from app.ml.config import MLConfig
from app.ml.feedback_data import samples_from_learning
from app.ml.predictor import ModelUnavailableError, ThreatPredictor
from app.ml.store import ModelStore, ModelStoreError
from app.ml.training import train_model
from app.services.event_service import EventService
from app.services.learning import LearningService

router = APIRouter(prefix="/api/ml")
_TRAIN_LOCK = threading.Lock()
NOTE = "ML prediction (decision support): not a confirmed attack and not the incident confidence."


def get_predictor(request: Request) -> ThreatPredictor:
    predictor = request.app.state.predictor
    if predictor is None:
        raise HTTPException(503, {"detail": "ML unavailable: ml_config.yaml missing or invalid", "code": "ml_not_configured"})
    return predictor


def _store(request: Request) -> tuple[ModelStore, MLConfig]:
    store, config = request.app.state.ml_store, request.app.state.ml_config
    if store is None or config is None:
        raise HTTPException(503, {"detail": "ML unavailable: ml_config.yaml missing or invalid", "code": "ml_not_configured"})
    return store, config


class MLPredictRequest(BaseModel):
    """Either stored event ids or explicit events (validated SecurityEvents). Unknown fields are rejected."""

    model_config = {"extra": "forbid"}
    event_ids: list[str] | None = Field(default=None, max_length=200)
    events: list[SecurityEvent] | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _one_source(self) -> "MLPredictRequest":
        if (self.event_ids is None) == (self.events is None):
            raise ValueError("give exactly one of event_ids or events")
        if not (self.event_ids or self.events):
            raise ValueError("at least one event is required")
        if self.event_ids and any(not i or len(i) > 64 for i in self.event_ids):
            raise ValueError("event_ids must be non-empty strings of at most 64 characters")
        return self


class MLTrainRequest(BaseModel):
    model_config = {"extra": "forbid"}
    activate: bool = False
    include_learning_records: bool = False
    samples_per_class: int | None = Field(default=None, ge=10, le=2000)


class MLActivateRequest(BaseModel):
    model_config = {"extra": "forbid"}
    model_version: str = Field(min_length=1, max_length=20, pattern=r"^rf-v[0-9]+$")


def _summary(meta: dict[str, Any], active: str | None) -> dict[str, Any]:
    m = meta.get("metrics", {})
    return {"model_version": meta["model_version"], "model_type": meta.get("model_type"), "training_timestamp": meta.get("training_timestamp"),
            "dataset_size": meta.get("dataset_size"), "feature_version": meta.get("feature_version"), "classes": meta.get("classes"),
            "accuracy": m.get("accuracy"), "macro_f1": m.get("macro", {}).get("f1"),
            "data_source": meta.get("data_source"), "active": meta["model_version"] == active}


@router.get("/status")
def ml_status(request: Request) -> dict[str, Any]:
    predictor: ThreatPredictor | None = request.app.state.predictor
    config: MLConfig | None = request.app.state.ml_config
    if predictor is None or config is None:
        return {"engine": "ML Prediction Engine", "kind": "Random Forest (decision support)", "autonomous_agent": False,
                "available": False, "error": "ml_config.yaml missing or invalid", "active_version": None, "versions": 0}
    return {**predictor.status(), "risk_thresholds": {"medium": config.risk.medium, "high": config.risk.high},
            "monitor_signal_probability": config.monitor.signal_probability, "labels": list(config.model.labels),
            "can_create_incidents": False, "can_execute_actions": False, "note": NOTE}


@router.get("/models")
def ml_models(request: Request) -> dict[str, Any]:
    store, _ = _store(request)
    active = store.active_version()
    return {"active_version": active, "models": [_summary(m, active) for m in reversed(store.versions())]}


@router.get("/metrics")
def ml_metrics(request: Request, model_version: str | None = None) -> dict[str, Any]:
    store, _ = _store(request)
    version = model_version or store.active_version()
    if version is None:
        raise HTTPException(503, {"detail": "no active ML model; train one explicitly (POST /api/ml/train)", "code": "model_unavailable"})
    try:
        meta = store.metadata(version)
    except ModelStoreError as exc:
        raise HTTPException(404, str(exc)) from None
    return {"model_version": version, "active": version == store.active_version(),
            "training_timestamp": meta.get("training_timestamp"), "dataset_size": meta.get("dataset_size"),
            "split": meta.get("split"), "data_source": meta.get("data_source"), "evaluation_scope": meta.get("evaluation_scope"),
            "metrics": meta.get("metrics"), "feature_importances": meta.get("feature_importances"),
            "hyperparameters": meta.get("hyperparameters"), "limitations": meta.get("limitations")}


@router.post("/predict")
def ml_predict(body: MLPredictRequest, request: Request, predictor: ThreatPredictor = Depends(get_predictor)) -> dict[str, Any]:
    """Predict from stored events (event_ids) or explicit events. Events are correlated like the Monitor does and
    every group is scored. Cloud context (privileged principal) is not available here, so that flag is 0."""
    if body.event_ids is not None:
        with ready_database(request).session() as session:
            events = EventService(session).get_events_by_ids(body.event_ids)
        missing = sorted(set(body.event_ids) - {e.event_id for e in events})
        if missing:
            raise HTTPException(404, {"detail": f"events not found: {missing[:5]}", "code": "events_not_found"})
    else:
        events = list(body.events or [])
    monitor_config = request.app.state.monitor_config
    if monitor_config is None:
        raise HTTPException(503, {"detail": "Monitor rules unavailable (needed for feature enrichment)", "code": "monitor_rules_missing"})
    items = [NormalizedEvent(event=e, fingerprint=uuid.uuid4().hex, ingest_format="security_event", stored=False) for e in events]
    enricher = Enricher(monitor_config, None)
    groups = []
    try:
        for group_items in correlate(items, monitor_config.correlation.window_seconds):
            group = enricher.build_group(group_items)
            groups.append({"group_id": group.group_id, "event_ids": group.event_ids, "prediction": predictor.predict_group(group)})
    except ModelUnavailableError as exc:
        raise HTTPException(503, {"detail": str(exc), "code": "model_unavailable"}) from None
    return {"groups": groups, "model_version": groups[0]["prediction"].model_version if groups else None, "note": NOTE}


@router.post("/train")
def ml_train(body: MLTrainRequest, request: Request) -> dict[str, Any]:
    """Explicitly train a NEW model version from simulator data (+ optionally labelled learning records). The active
    model is unchanged unless activate=true."""
    store, config = _store(request)
    monitor_config = request.app.state.monitor_config
    if monitor_config is None:
        raise HTTPException(503, {"detail": "Monitor rules unavailable (needed for feature enrichment)", "code": "monitor_rules_missing"})
    if not _TRAIN_LOCK.acquire(blocking=False):
        raise HTTPException(409, {"detail": "a training run is already in progress", "code": "training_in_progress"})
    try:
        extra, skipped = [], {}
        if body.include_learning_records:
            with ready_database(request).session() as session:
                extra, skipped = samples_from_learning(LearningService(session).list(limit=10000), config)
        meta = train_model(config, monitor_config, store, learning_samples=extra, activate=body.activate,
                           samples_per_class=body.samples_per_class)
    finally:
        _TRAIN_LOCK.release()
    meta["learning_records_skipped"] = skipped
    record_audit(request, AuditEntry(actor=HumanActor.ANALYST, action="ml.model_trained", decision="trained",
                                     result=f"{meta['model_version']} trained (accuracy {meta['metrics']['accuracy']}, simulator data)",
                                     details={"model_version": meta["model_version"], "dataset_size": meta["dataset_size"],
                                              "activated": body.activate, "learning_records_used": len(extra)}))
    return {**_summary(meta, store.active_version()), "metrics": meta["metrics"], "learning_records_used": len(extra),
            "learning_records_skipped": skipped, "limitations": meta["limitations"]}


@router.post("/activate")
def ml_activate(body: MLActivateRequest, request: Request) -> dict[str, Any]:
    """Explicitly make an existing version the active model (training never does this silently)."""
    store, _ = _store(request)
    try:
        store.set_active(body.model_version)
    except ModelStoreError as exc:
        raise HTTPException(404, str(exc)) from None
    record_audit(request, AuditEntry(actor=HumanActor.ANALYST, action="ml.model_activated", decision="activated",
                                     result=f"{body.model_version} is now the active ML model",
                                     details={"model_version": body.model_version}))
    return {"active_version": body.model_version}
