"""ML threat prediction (Phase 9) tests. Training data is simulator-generated; the model is decision support only:
it can never create incidents, execute actions or approve anything."""

import json
import random
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.agents.monitor.agent import MonitorAgent
from app.agents.monitor.config import INDICATORS
from app.agents.monitor.correlation import correlate
from app.agents.monitor.decision import decide
from app.agents.monitor.enrichment import Enricher
from app.agents.monitor.models import EventGroup, MonitorRunRequest, NormalizedEvent
from app.agents.triage.agent import TriageAgent, TriageRunRequest
from app.agents.triage.config import load_triage_config
from app.agents.triage.context import ContextBuilder
from app.agents.triage.validation import TriageValidationError, validate_decision as validate_triage
from app.config import Settings
from app.domain.enums import AgentRunStatus, HumanActor
from app.domain.learning import FeedbackType, HumanFeedback, LearningRecord, Recommendation
from app.domain.ml import MLPrediction
from app.llm.mock import MockLLMProvider
from app.main import create_app
from app.ml.config import MLConfig, MLConfigError, load_ml_config
from app.ml.dataset import generate_dataset
from app.ml.feedback_data import samples_from_learning
from app.ml.features import FEATURE_NAMES, FEATURES, FeatureError, extract_features, to_vector
from app.ml.predictor import ModelUnavailableError, ThreatPredictor
from app.ml.store import ModelStore, ModelStoreError
from app.ml.training import train_model
from app.services.event_service import EventService
from app.services.incident_service import IncidentService
from app.services.learning import LearningService
from app.simulator.attacks import AttackSimulator
from app.simulator.cloud import CloudSimulator
from app.simulator.events import EventGenerator
from app.tools.base import ToolContext
from app.tools.executor import ToolExecutor
from app.tools.registry import build_default_registry
from tests.monitor_fixtures import config as monitor_config
from tests.test_triage import answer as triage_answer

CONFIG_DIR = Settings().config_dir
CONFIG = load_ml_config(CONFIG_DIR)
MONITOR = monitor_config()
ML_SRC = Path(__file__).resolve().parent.parent / "app" / "ml"


# ================================================================================= builders
def make_group(events, cloud=None) -> EventGroup:
    items = [NormalizedEvent(event=e, fingerprint=f"fp-{i}", ingest_format="security_event", stored=True) for i, e in enumerate(events)]
    lookup = None
    if cloud is not None:
        lookup = lambda t, i: (getattr(cloud, {"IAMUser": "get_user", "EC2Instance": "get_instance", "S3Bucket": "get_bucket"}[t])(i).model_dump(mode="json")  # noqa: E731
                               if t in ("IAMUser", "EC2Instance", "S3Bucket") and i not in ("*", "") else None)
    groups = [Enricher(MONITOR, lookup).build_group(g) for g in correlate(items, MONITOR.correlation.window_seconds)]
    return max(groups, key=lambda g: len(g.events))


def scenario_events(name: str, seed: int = 7):
    cloud = CloudSimulator()
    rng = random.Random(seed)
    events = AttackSimulator(cloud, EventGenerator(rng=rng), rng).run(name).events
    return events, cloud


def benign_events(seed: int = 3, count: int = 4):
    return EventGenerator(rng=random.Random(seed)).normal_batch(count)


@pytest.fixture(scope="module")
def trained(tmp_path_factory) -> ModelStore:
    """One small trained + activated model shared by the module (a real Random Forest on simulator data)."""
    store = ModelStore(tmp_path_factory.mktemp("ml-models"))
    train_model(CONFIG, MONITOR, store, activate=True, samples_per_class=60)
    return store


@pytest.fixture()
def predictor(trained) -> ThreatPredictor:
    return ThreatPredictor(trained, CONFIG)


# ==================================================================================== config
def test_config_is_valid_and_thresholds_live_in_yaml() -> None:
    assert CONFIG.model.benign_label == "BENIGN" and len(CONFIG.model.labels) == 6
    assert {"IAM_PRIVILEGE_ESCALATION", "CREDENTIAL_MISUSE", "SUSPICIOUS_NETWORK_ACTIVITY", "S3_UNAUTHORIZED_ACCESS",
            "EC2_COMPROMISE", "BENIGN"} == set(CONFIG.model.labels)
    assert (CONFIG.risk_level(0.1), CONFIG.risk_level(0.5), CONFIG.risk_level(0.9)) == ("low", "medium", "high")
    assert CONFIG.risk_level(CONFIG.risk.high) == "high" and CONFIG.risk_level(CONFIG.risk.medium) == "medium"


def test_config_validation(tmp_path) -> None:
    good = (CONFIG_DIR / "ml_config.yaml").read_text(encoding="utf-8")
    (tmp_path / "ml_config.yaml").write_text(good.replace("medium: 0.40", "medium: 0.90"), encoding="utf-8")
    with pytest.raises(MLConfigError, match="below"):
        load_ml_config(tmp_path)
    (tmp_path / "ml_config.yaml").write_text(good.replace("benign_label: BENIGN", "benign_label: NOPE"), encoding="utf-8")
    with pytest.raises(MLConfigError):
        load_ml_config(tmp_path)
    with pytest.raises(MLConfigError, match="not found"):
        load_ml_config(tmp_path / "missing")


# ============================================================================== features
def test_feature_extraction_is_complete_and_ordered() -> None:
    events, cloud = scenario_events("iam_privilege_escalation")
    f = extract_features(make_group(events, cloud))
    assert tuple(f) == FEATURE_NAMES and set(FEATURES) == set(FEATURE_NAMES)
    assert f["event_count"] == 4 and f["n_attach_admin_policy"] == 1 and f["n_get_secret_value"] == 1
    assert f["privileged_principal"] == 1.0 and f["untrusted_ip_ratio"] == 1.0 and f["sensitive_resource_count"] >= 1
    assert f["suspicious_api_count"] == 3 and f["unique_source_ips"] == 1 and f["network_event_count"] == 0
    assert f["event_frequency_per_min"] > 0 and f["burst_events_60s"] >= 1 and f["mean_gap_seconds"] > 0
    assert all(isinstance(v, float) for v in f.values())


def test_features_contain_no_identities_addresses_or_ground_truth() -> None:
    events, cloud = scenario_events("credential_misuse")
    group = make_group(events, cloud)
    f = extract_features(group)
    blob = json.dumps(f)
    for text in ("alice", "bob", "198.51", "203.0.113", "company-data", "AKIA", "scenario"):
        assert text not in blob
    tampered = [e.model_copy(update={"details": {**e.details, "scenario_id": "changed", "step": 99}}) for e in events]
    assert extract_features(make_group(tampered, cloud)) == f                 # simulator ground truth is never read


def test_missing_and_malformed_values_are_handled_safely() -> None:
    assert to_vector({}) == [0.0] * len(FEATURE_NAMES)
    vector = to_vector({"event_count": "3", "duration_seconds": None, "burst_events_60s": float("nan"), "n_login": "x",
                        "min_gap_seconds": float("inf"), "unknown_feature": 5})
    assert vector[FEATURE_NAMES.index("event_count")] == 3.0
    assert all(v == 0.0 for i, v in enumerate(vector) if FEATURE_NAMES[i] != "event_count")
    with pytest.raises(FeatureError):
        extract_features(EventGroup(group_id="GRP-EMPTY", events=[]))
    single = extract_features(make_group(benign_events(count=1)))          # one event: gaps default to 0
    assert single["event_count"] == 1 and single["min_gap_seconds"] == single["mean_gap_seconds"] == 0.0


def test_ml_indicator_is_never_fed_back_into_the_model() -> None:
    events, cloud = scenario_events("iam_privilege_escalation")
    group = make_group(events, cloud)
    before = extract_features(group)
    group.group_indicators.append("ml_threat_predicted")
    assert extract_features(group) == before


# ================================================================================== dataset
def test_dataset_generation_is_deterministic_balanced_and_chronological() -> None:
    a = generate_dataset(CONFIG, MONITOR, seed=11, samples_per_class=12)
    b = generate_dataset(CONFIG, MONITOR, seed=11, samples_per_class=12)
    assert [(s.label, s.features) for s in a] == [(s.label, s.features) for s in b]
    assert [s.label for s in generate_dataset(CONFIG, MONITOR, seed=12, samples_per_class=12)] != [s.label for s in a]
    counts = {label: sum(s.label == label for s in a) for label in CONFIG.model.labels}
    assert set(counts.values()) == {12} and len(a) == 72
    assert [s.time for s in a] == sorted(s.time for s in a) and len({s.time for s in a}) == len(a)
    assert all(tuple(s.features) == FEATURE_NAMES for s in a) and all(s.source == "simulator" for s in a)


def test_labels_come_from_the_generating_scenario_not_from_text() -> None:
    data = generate_dataset(CONFIG, MONITOR, seed=5, samples_per_class=30)
    net = [s for s in data if s.label == "SUSPICIOUS_NETWORK_ACTIVITY"]
    assert all(s.features["n_network_flow_anomaly"] >= 1 and s.features["n_execute_command"] == 0 for s in net)
    iam = [s for s in data if s.label == "IAM_PRIVILEGE_ESCALATION"]
    assert sum(s.features["n_attach_admin_policy"] >= 1 for s in iam) >= len(iam) * 0.5


# ===================================================================================== training
def test_training_produces_a_versioned_persisted_model_with_metrics(tmp_path) -> None:
    store = ModelStore(tmp_path)
    meta = train_model(CONFIG, MONITOR, store, samples_per_class=40)
    assert meta["model_version"] == "rf-v1" and meta["active"] is False and store.active_version() is None
    assert meta["feature_version"] == "f1" and meta["classes"] == sorted(CONFIG.model.labels)
    assert meta["dataset_size"]["total"] == 240 and meta["dataset_size"]["train"] + meta["dataset_size"]["test"] == 240
    assert meta["training_timestamp"] and meta["data_source"].startswith("simulator-generated") and meta["seed"] == 42
    assert meta["split"]["method"] == "chronological" and meta["split"]["train_until"] < meta["split"]["test_from"]
    m = meta["metrics"]
    assert 0.0 <= m["accuracy"] <= 1.0 and set(m["macro"]) == {"precision", "recall", "f1"}
    assert set(m["per_class"]) == set(CONFIG.model.labels) and m["test_samples"] == meta["dataset_size"]["test"]
    cm = m["confusion_matrix"]
    assert cm["labels"] == list(CONFIG.model.labels) and sum(map(sum, cm["matrix"])) == m["test_samples"]
    t = m["threat_detection"]
    assert t["true_positives"] + t["true_negatives"] + t["false_positives"] + t["false_negatives"] == m["test_samples"]
    assert {"false_positives", "false_negatives", "precision", "recall", "f1"} <= set(t)
    assert any("simulator" in l for l in meta["limitations"]) and meta["model_sha256"]
    assert (tmp_path / "rf-v1" / "model.joblib").is_file() and (tmp_path / "rf-v1" / "metadata.json").is_file()


def test_training_is_reproducible(tmp_path) -> None:
    a = train_model(CONFIG, MONITOR, ModelStore(tmp_path / "a"), samples_per_class=25)["metrics"]
    b = train_model(CONFIG, MONITOR, ModelStore(tmp_path / "b"), samples_per_class=25)["metrics"]
    assert a == b


def test_training_never_silently_replaces_the_active_model(tmp_path) -> None:
    store = ModelStore(tmp_path)
    train_model(CONFIG, MONITOR, store, activate=True, samples_per_class=20)
    second = train_model(CONFIG, MONITOR, store, samples_per_class=20)
    assert second["model_version"] == "rf-v2" and store.active_version() == "rf-v1"
    assert [m["model_version"] for m in store.versions()] == ["rf-v1", "rf-v2"]
    store.set_active("rf-v2")
    assert store.active_version() == "rf-v2"
    with pytest.raises(ModelStoreError):
        store.set_active("rf-v9")
    with pytest.raises(ModelStoreError):
        store.save(object(), {"model_version": "rf-v1"})                       # versions are never overwritten
    with pytest.raises(ModelStoreError):
        store.metadata("../../etc")


def test_a_tampered_model_file_is_refused(tmp_path) -> None:
    store = ModelStore(tmp_path)
    train_model(CONFIG, MONITOR, store, activate=True, samples_per_class=20)
    (tmp_path / "rf-v1" / "model.joblib").write_bytes(b"not the model any more")
    with pytest.raises(ModelStoreError, match="integrity"):
        store.load("rf-v1")
    predictor = ThreatPredictor(store, CONFIG)
    status = predictor.status()
    assert status["available"] is False and "integrity" in status["error"]
    with pytest.raises(ModelUnavailableError):
        predictor.predict_features({})


# =================================================================================== prediction
def test_model_unavailable_without_an_active_model(tmp_path) -> None:
    predictor = ThreatPredictor(ModelStore(tmp_path / "empty"), CONFIG)
    assert predictor.status()["available"] is False and "train one explicitly" in predictor.status()["error"]
    with pytest.raises(ModelUnavailableError):
        predictor.predict_features({"event_count": 3})
    assert ThreatPredictor(ModelStore(tmp_path), CONFIG).status()["versions"] == 0


def test_iam_privilege_escalation_is_predicted(predictor) -> None:
    events, cloud = scenario_events("iam_privilege_escalation")
    p = predictor.predict_group(make_group(events, cloud))
    assert isinstance(p, MLPrediction) and p.prediction == "IAM_PRIVILEGE_ESCALATION"
    assert p.threat_probability >= 0.75 and p.risk_level == "high" and p.is_threat is True
    assert p.model_version == "rf-v1" and p.feature_version == "f1" and p.model_type == "RandomForestClassifier"
    assert p.prediction_probability <= p.threat_probability + 1e-9 or p.prediction != "BENIGN"
    assert abs(sum(p.class_probabilities.values()) - 1.0) < 0.01 and set(p.class_probabilities) == set(CONFIG.model.labels)
    assert p.important_features and len(p.important_features) <= CONFIG.explain.top_features
    assert all(f.value != 0 and f.description for f in p.important_features)
    assert "not a confirmed attack" in p.note and p.data_source == "simulator-generated"
    assert set(p.features) == set(FEATURE_NAMES)


def test_each_scenario_and_benign_activity_is_classified(predictor) -> None:
    expected = {"credential_misuse": "CREDENTIAL_MISUSE", "public_s3_exposure": "S3_UNAUTHORIZED_ACCESS",
                "ec2_compromise": "EC2_COMPROMISE"}
    for scenario, label in expected.items():
        events, cloud = scenario_events(scenario)
        p = predictor.predict_group(make_group(events, cloud))
        assert p.prediction == label and p.is_threat, (scenario, p.prediction, p.threat_probability)
    benign = predictor.predict_group(make_group(benign_events()))
    assert benign.prediction == "BENIGN" and benign.risk_level == "low" and benign.is_threat is False
    assert benign.threat_probability < CONFIG.risk.medium


def test_ml_probability_is_not_incident_confidence(predictor) -> None:
    events, cloud = scenario_events("iam_privilege_escalation")
    group = make_group(events, cloud)
    p = predictor.predict_group(group)
    decision = decide(group, MONITOR)                                       # the Monitor's own confidence
    assert decision.confidence != p.threat_probability
    assert not hasattr(decision, "threat_probability") and "confidence" not in p.model_dump()


def test_risk_thresholds_come_from_configuration(trained) -> None:
    strict = MLConfig.model_validate({**CONFIG.model_dump(), "risk": {"medium": 0.6, "high": 0.9999},
                                      "monitor": {"signal_probability": 0.9999}})
    events, cloud = scenario_events("iam_privilege_escalation")
    p = ThreatPredictor(trained, strict).predict_group(make_group(events, cloud))
    assert p.risk_level in ("medium", "high") and p.is_threat is False or p.threat_probability >= 0.9999


def test_feature_set_mismatch_is_refused(tmp_path) -> None:
    store = ModelStore(tmp_path)
    meta = train_model(CONFIG, MONITOR, store, activate=True, samples_per_class=15)
    other = MLConfig.model_validate({**CONFIG.model_dump(), "model": {**CONFIG.model_dump()["model"], "feature_version": "f2"}})
    assert ThreatPredictor(store, other).status()["available"] is False and meta["feature_version"] == "f1"


# ============================================================================ Monitor integration
def run_monitor(database, cloud, events, predictor=None):
    tools = ToolExecutor(ToolContext(cloud=cloud, database=database, registry=build_default_registry(), config_dir=CONFIG_DIR),
                         audit_sink=lambda e: None)
    with database.session() as session:
        EventService(session).save_events(events)
    agent = MonitorAgent(database, MONITOR, tools, audit_sink=lambda e: None, predictor=predictor)
    return agent.run(MonitorRunRequest(event_ids=[e.event_id for e in events]))


def incident_of(database, report):
    with database.session() as session:
        return IncidentService(session).get(report.incidents_created[0])


def test_monitor_attaches_the_prediction_and_creates_the_incident_from_rules(database, cloud, trained) -> None:
    events, _ = scenario_events("iam_privilege_escalation")
    events = AttackSimulator(cloud).run("iam_privilege_escalation").events
    report = run_monitor(database, cloud, events, ThreatPredictor(trained, CONFIG))
    incident = incident_of(database, report)
    assert incident.ml_prediction.prediction == "IAM_PRIVILEGE_ESCALATION" and incident.ml_prediction.model_version == "rf-v1"
    assert "ml_threat_predicted" in incident.normalized_event["group_indicators"]
    assert report.correlated_groups[0].ml_prediction.prediction == "IAM_PRIVILEGE_ESCALATION"
    assert "high_severity" in incident.normalized_event["group_indicators"]                 # rules still fired
    assert incident.confidence != incident.ml_prediction.threat_probability                   # distinct numbers


def test_ml_alone_never_creates_an_incident(database, cloud) -> None:
    class AlwaysThreat:
        def predict_group(self, group):
            return MLPrediction(prediction="IAM_PRIVILEGE_ESCALATION", threat_probability=0.99, prediction_probability=0.99,
                                risk_level="high", is_threat=True, model_version="stub", feature_version="f1",
                                important_features=[], class_probabilities={"IAM_PRIVILEGE_ESCALATION": 0.99}, features={})
    report = run_monitor(database, cloud, benign_events(count=5), AlwaysThreat())
    assert report.incidents_created == [] and report.incidents_updated == []
    assert report.correlated_groups[0].decision == "no_incident"
    assert report.correlated_groups[0].ml_prediction.threat_probability == 0.99            # recorded, but not acted on
    with database.session() as session:
        assert IncidentService(session).list_incidents() == []


def test_ml_indicator_cannot_satisfy_the_incident_rules_by_itself() -> None:
    assert "ml_threat_predicted" in INDICATORS
    events = benign_events(count=5)
    group = make_group(events)
    group.group_indicators.append("ml_threat_predicted")
    assert decide(group, MONITOR).create_incident is False
    assert "ml_threat_predicted" in decide(group, MONITOR).indicators


def test_a_failing_or_missing_model_does_not_break_the_monitor(database, cloud, tmp_path) -> None:
    class Broken:
        def predict_group(self, group):
            raise RuntimeError("model exploded")
    events = AttackSimulator(cloud).run("iam_privilege_escalation").events
    report = run_monitor(database, cloud, events, Broken())
    assert len(report.incidents_created) == 1 and incident_of(database, report).ml_prediction is None
    cloud2 = CloudSimulator()
    events2 = AttackSimulator(cloud2).run("iam_privilege_escalation").events
    unavailable = ThreatPredictor(ModelStore(tmp_path / "none"), CONFIG)
    second = run_monitor(database, cloud2, events2, unavailable)          # same principal: merged into the open incident
    assert len(second.incidents_created) + len(second.incidents_updated) == 1


def test_ml_supports_the_confidence_but_the_rules_decide(database, cloud, trained) -> None:
    events = AttackSimulator(cloud).run("iam_privilege_escalation").events
    with_ml = incident_of(database, run_monitor(database, cloud, events, ThreatPredictor(trained, CONFIG))).confidence
    from app.database.connection import Database, create_db_engine
    from app.database.models import Base
    engine = create_db_engine("sqlite://")
    Base.metadata.create_all(engine)
    other = Database(engine)
    other.ensure_schema()
    cloud2 = CloudSimulator()
    events2 = AttackSimulator(cloud2).run("iam_privilege_escalation").events
    without = incident_of(other, run_monitor(other, cloud2, events2, None)).confidence
    assert with_ml >= without and with_ml <= MONITOR.confidence.max_confidence


# ============================================================================ Triage integration
def triage_incident(database, cloud, trained):
    events = AttackSimulator(cloud).run("iam_privilege_escalation").events
    report = run_monitor(database, cloud, events, ThreatPredictor(trained, CONFIG))
    return incident_of(database, report)


def test_triage_receives_the_prediction_as_context_not_evidence(database, cloud, trained) -> None:
    incident = triage_incident(database, cloud, trained)
    tools = ToolExecutor(ToolContext(cloud=cloud, database=database, registry=build_default_registry(), config_dir=CONFIG_DIR),
                         audit_sink=lambda e: None)
    context = ContextBuilder(load_triage_config(CONFIG_DIR), tools).build(incident)
    block = context.payload["ml_prediction"]
    assert block["prediction"] == "IAM_PRIVILEGE_ESCALATION" and block["ref"] == "ML1" and block["model"] == f"Random Forest {incident.ml_prediction.model_version}"
    assert block["threat_probability"] == round(incident.ml_prediction.threat_probability, 2) == context.ml_probability
    assert "NOT a confirmed attack" in block["note"] and "never reuse" in block["note"]
    assert "ML1" in context.facts and context.facts["ML1"].kind == "ml_prediction"
    assert "features" not in json.dumps(context.payload)                        # raw feature vector is not sent


def test_triage_still_assesses_independently(database, cloud, trained) -> None:
    incident = triage_incident(database, cloud, trained)
    tools = ToolExecutor(ToolContext(cloud=cloud, database=database, registry=build_default_registry(), config_dir=CONFIG_DIR),
                         audit_sink=lambda e: None)
    provider = MockLLMProvider([triage_answer(confidence=0.63)])
    report = TriageAgent(database, load_triage_config(CONFIG_DIR), provider, tools, audit_sink=lambda e: None).run(
        TriageRunRequest(incident_id=incident.incident_id))
    assert report.status == AgentRunStatus.SUCCESS and report.triage.confidence == 0.63
    assert report.triage.confidence != incident.ml_prediction.threat_probability
    assert "ml_prediction" in provider.calls[0]["user"] and "never reuse" in provider.calls[0]["user"]


def test_copying_the_ml_probability_as_confidence_is_rejected(database, cloud, trained) -> None:
    incident = triage_incident(database, cloud, trained)
    tools = ToolExecutor(ToolContext(cloud=cloud, database=database, registry=build_default_registry(), config_dir=CONFIG_DIR),
                         audit_sink=lambda e: None)
    config = load_triage_config(CONFIG_DIR)
    context = ContextBuilder(config, tools).build(incident)
    copied = context.ml_probability
    with pytest.raises(TriageValidationError, match="ML threat probability"):
        validate_triage(triage_answer(confidence=copied), set(context.facts), config, copied)
    validate_triage(triage_answer(confidence=0.5 if copied != 0.5 else 0.6), set(context.facts), config, copied)
    validate_triage(triage_answer(confidence=copied), set(context.facts), config, None)   # no ML -> no guard


# ============================================================================ feedback integration
def record(**kw) -> LearningRecord:
    base = dict(incident_id="INC-1", incident_category="iam", attack_type="x", initial_severity="high", final_severity="high",
                auto_feedback_type=FeedbackType.SUCCESSFUL_RESPONSE, feedback_type=FeedbackType.SUCCESSFUL_RESPONSE,
                recommendation=Recommendation.NO_FURTHER_ACTION, successful=True,
                ml_prediction="IAM_PRIVILEGE_ESCALATION", ml_features={n: 1.0 for n in FEATURE_NAMES},
                human_feedback=HumanFeedback.CORRECT, timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc))
    return LearningRecord(**{**base, **kw})


def test_only_human_confirmed_records_become_training_samples() -> None:
    good = record()
    records = [good, record(human_feedback=None), record(ml_features=None),
               record(ml_prediction="NOT_A_LABEL"),
               record(human_feedback=HumanFeedback.INCORRECT, feedback_type=FeedbackType.FAILED_RESPONSE, successful=False),
               record(auto_feedback_type=FeedbackType.REGRESSION_DETECTED, feedback_type=FeedbackType.REGRESSION_DETECTED, human_feedback=None)]
    samples, skipped = samples_from_learning(records, CONFIG)
    assert [(s.label, s.source) for s in samples] == [("IAM_PRIVILEGE_ESCALATION", "learning_record")]
    assert skipped == {"no_ml_features": 1, "no_human_confirmation": 2, "unknown_label": 1, "retry_or_regression": 1}


def test_learning_records_are_added_to_the_training_set_only(tmp_path) -> None:
    samples, _ = samples_from_learning([record(), record()], CONFIG)
    meta = train_model(CONFIG, MONITOR, ModelStore(tmp_path), learning_samples=samples, samples_per_class=20)
    size = meta["dataset_size"]
    assert size["learning_records"] == 2 and size["total"] == 122 and size["test"] == 24 and size["train"] == 98 and size["simulator_generated"] == 120
    assert any("TRAINING set only" in l for l in meta["limitations"])


# ======================================================================================= API
@pytest.fixture()
def api(cloud, database, tmp_path):
    def build(model_dir=None) -> TestClient:
        settings = Settings(ml_model_dir=str(model_dir or tmp_path / "models"))
        return TestClient(create_app(cloud=cloud, database=database, settings=settings, llm_provider=None))
    return build


def event_json(events):
    return [e.model_dump(mode="json") for e in events]


def test_api_without_a_model(api) -> None:
    with api() as client:
        status = client.get("/api/ml/status").json()
        assert status["available"] is False and status["autonomous_agent"] is False and status["engine"] == "ML Prediction Engine"
        assert status["can_create_incidents"] is False and status["can_execute_actions"] is False
        assert client.get("/api/ml/models").json() == {"active_version": None, "models": []}
        metrics = client.get("/api/ml/metrics")
        assert metrics.status_code == 503 and metrics.json()["detail"]["code"] == "model_unavailable"
        events = AttackSimulator(CloudSimulator()).run("iam_privilege_escalation").events
        response = client.post("/api/ml/predict", json={"events": event_json(events)})
        assert response.status_code == 503 and response.json()["detail"]["code"] == "model_unavailable"


def test_api_train_activate_predict_metrics(api, cloud, database) -> None:
    with api() as client:
        trained_ = client.post("/api/ml/train", json={"samples_per_class": 30}).json()
        assert trained_["model_version"] == "rf-v1" and trained_["active"] is False
        assert client.get("/api/ml/status").json()["available"] is False                    # training did NOT activate it
        assert client.post("/api/ml/activate", json={"model_version": "rf-v9"}).status_code == 404
        assert client.post("/api/ml/activate", json={"model_version": "rf-v1"}).json() == {"active_version": "rf-v1"}
        status = client.get("/api/ml/status").json()
        assert status["available"] is True and status["active_version"] == "rf-v1" and status["risk_thresholds"]["high"] == 0.75
        models = client.get("/api/ml/models").json()
        assert models["active_version"] == "rf-v1" and models["models"][0]["active"] is True and models["models"][0]["accuracy"] is not None
        metrics = client.get("/api/ml/metrics").json()
        assert metrics["metrics"]["confusion_matrix"]["labels"] and metrics["limitations"] and metrics["data_source"].startswith("simulator")
        assert {"false_positives", "false_negatives"} <= set(metrics["metrics"]["threat_detection"])
        # explicit events
        events = AttackSimulator(cloud).run("iam_privilege_escalation").events
        state = cloud.get_cloud_state()
        body = client.post("/api/ml/predict", json={"events": event_json(events)}).json()
        prediction = body["groups"][0]["prediction"]
        assert body["model_version"] == "rf-v1" and prediction["prediction"] in CONFIG.model.labels
        assert set(prediction) >= {"prediction", "threat_probability", "risk_level", "model_version", "important_features"}
        assert 0.0 <= prediction["threat_probability"] <= 1.0 and "not the incident confidence" in body["note"]
        # stored events
        with database.session() as session:
            EventService(session).save_events(events)
        stored = client.post("/api/ml/predict", json={"event_ids": [e.event_id for e in events]}).json()
        assert stored["groups"][0]["event_ids"] and stored["groups"][0]["prediction"]["model_version"] == "rf-v1"
        assert cloud.get_cloud_state() == state                                              # prediction changes nothing
        assert client.get("/api/incidents").json() == []                                      # and creates no incident
        audit = {e["action"] for e in client.get("/api/audit").json()}
        assert {"ml.model_trained", "ml.model_activated"} <= audit
        assert client.post("/api/ml/train", json={"samples_per_class": 20}).json()["model_version"] == "rf-v2"
        assert client.get("/api/ml/status").json()["active_version"] == "rf-v1"              # still the same active model


def test_api_validation_and_errors(api, cloud) -> None:
    with api() as client:
        client.post("/api/ml/train", json={"samples_per_class": 20, "activate": True})
        good = event_json(AttackSimulator(cloud).run("iam_privilege_escalation").events)
        for body in ({}, {"event_ids": []}, {"events": []}, {"event_ids": ["a"], "events": good}, {"events": good, "execute": True},
                     {"events": [{"event_type": "Login"}]}, {"events": [{**good[0], "source_ip": "not-an-ip"}]},
                     {"event_ids": [""]}, {"event_ids": "x"}):
            assert client.post("/api/ml/predict", json=body).status_code == 422, body
        missing = client.post("/api/ml/predict", json={"event_ids": ["does-not-exist"]})
        assert missing.status_code == 404 and missing.json()["detail"]["code"] == "events_not_found"
        for path, body in (("/api/ml/train", {"samples_per_class": 5}), ("/api/ml/train", {"retrain": True}),
                           ("/api/ml/activate", {"model_version": "../x"}), ("/api/ml/activate", {})):
            assert client.post(path, json=body).status_code == 422, (path, body)


def test_api_training_with_learning_records(api, database) -> None:
    with database.session() as session:
        LearningService(session).save(record())
        LearningService(session).save(record(human_feedback=None))
    with api() as client:
        out = client.post("/api/ml/train", json={"samples_per_class": 20, "include_learning_records": True}).json()
        assert out["learning_records_used"] == 1 and out["learning_records_skipped"]["no_human_confirmation"] == 1


def test_api_is_unavailable_but_harmless_without_ml_config(cloud, database, tmp_path) -> None:
    with TestClient(create_app(cloud=cloud, database=database, settings=Settings(config_dir=tmp_path), llm_provider=None)) as client:
        assert client.get("/api/ml/status").json()["available"] is False
        assert client.get("/api/ml/models").status_code == 503
        assert client.post("/api/ml/predict", json={"event_ids": ["x"]}).status_code == 503
        assert client.get("/api/healthz").status_code == 200


# =================================================================================== security
def test_ml_read_path_has_no_tools_cloud_approvals_llm_or_shell() -> None:
    for name in ("predictor.py", "features.py", "store.py", "config.py", "feedback_data.py"):
        code = "\n".join(l for l in (ML_SRC / name).read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith(("#", '"""')))
        assert not re.search(r"^\s*(from|import)\s+app\.(tools|simulator|llm|services\.approvals|agents\.remediation|agents\.verification)", code, re.M), name
        assert not re.search(r"ToolExecutor|ToolRequest|CloudSimulator|ApprovalService|\.cloud\.", code), name
        assert not re.search(r"^\s*(from|import)\s+(httpx|requests|urllib|socket|subprocess)", code, re.M), name
        assert not re.search(r"\b(subprocess|os\.system|os\.popen|eval|exec)\b", code), name
    routes = (Path(__file__).resolve().parent.parent / "app" / "api" / "ml_routes.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*(from|import)\s+app\.(tools|simulator|services\.approvals)", routes, re.M)
    assert "get_tool_executor" not in routes and "ToolRequest" not in routes


def test_the_predictor_has_no_way_to_act(predictor) -> None:
    public = {n for n in dir(predictor) if not n.startswith("_")}
    assert public == {"status", "predict_group", "predict_features"}
    assert not any(hasattr(predictor, n) for n in ("tools", "executor", "cloud", "approve", "execute", "registry"))


def test_ml_cannot_use_any_tool_permission() -> None:
    from app.tools.registry import DEFAULT_PERMISSIONS
    assert "ML" not in {getattr(a, "name", str(a)) for a in DEFAULT_PERMISSIONS}          # no ML actor exists in the permission matrix


def test_ml_state_never_contains_secrets(database, cloud, trained) -> None:
    keys = [k.key_id for u in ("alice", "bob") for k in cloud.get_user(u).access_keys]
    events = AttackSimulator(cloud).run("iam_privilege_escalation").events
    incident = incident_of(database, run_monitor(database, cloud, events, ThreatPredictor(trained, CONFIG)))
    blob = json.dumps(incident.ml_prediction.model_dump(mode="json"))
    assert keys and not any(k in blob for k in keys) and "alice" not in blob and "198.51" not in blob


def test_metadata_keeps_the_honest_limitations(trained) -> None:
    meta = trained.metadata("rf-v1")
    assert "not real-world" in meta["evaluation_scope"] and len(meta["limitations"]) >= 4 and meta["metrics"]["test_samples"] > 0
