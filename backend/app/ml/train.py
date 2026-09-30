"""Command line training:  python -m app.ml.train [--activate] [--samples-per-class N]

Explicit only: nothing in the application trains a model automatically."""

import argparse
import json

from app.agents.monitor.config import load_monitor_config
from app.config import get_settings
from app.ml.config import load_ml_config
from app.ml.store import ModelStore
from app.ml.training import train_model


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a new Random Forest model version from simulator data.")
    parser.add_argument("--activate", action="store_true", help="make the new version the active model")
    parser.add_argument("--samples-per-class", type=int, default=None)
    args = parser.parse_args()
    settings = get_settings()
    config = load_ml_config(settings.config_dir)
    store = ModelStore(config.model_dir() if not settings.ml_model_dir else __import__("pathlib").Path(settings.ml_model_dir))
    meta = train_model(config, load_monitor_config(settings.config_dir), store, activate=args.activate,
                       samples_per_class=args.samples_per_class)
    print(json.dumps({k: meta[k] for k in ("model_version", "dataset_size", "active")}, indent=1))
    m = meta["metrics"]
    print(f"accuracy {m['accuracy']}  macro-F1 {m['macro']['f1']}  threat precision {m['threat_detection']['precision']} "
          f"recall {m['threat_detection']['recall']}  (simulator-generated held-out data, not real-world)")


if __name__ == "__main__":
    main()
