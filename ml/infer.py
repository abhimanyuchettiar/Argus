"""Load the trained classifier and produce a contract-shaped verdict."""

import math
import os
from pathlib import Path

import joblib
import pandas as pd

try:
    from .train import FEATURE_COLUMNS
except ImportError:  # Support running infer.py directly from the ml directory.
    from train import FEATURE_COLUMNS

_model = None


def load_model(path: str | None = None):
    """Load a trained classifier when present; otherwise use explicit demo heuristics."""
    global _model
    model_path = Path(path or os.getenv("ARGUS_MODEL_PATH", Path(__file__).with_name("model.joblib")))
    if not model_path.is_file():
        _model = None
        return None
    _model = joblib.load(model_path)
    return _model


def severity_from(label: str, confidence: float) -> str:
    if label == "normal":
        return "LOW"
    if confidence >= 0.9:
        return "HIGH"
    if confidence >= 0.6:
        return "MEDIUM"
    return "LOW"


def predict(features: dict) -> dict:
    """Classify exactly the 15 named flow features from docs/FLOW_SCHEMA.md."""
    if not isinstance(features, dict):
        raise ValueError("features must be a JSON object")
    missing = [name for name in FEATURE_COLUMNS if name not in features]
    unexpected = [name for name in features if name not in FEATURE_COLUMNS]
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise ValueError("Invalid feature fields (" + "; ".join(details) + ")")
    try:
        values = {name: float(features[name]) for name in FEATURE_COLUMNS}
    except (TypeError, ValueError) as exc:
        raise ValueError("All feature values must be numeric") from exc
    if not all(math.isfinite(value) for value in values.values()):
        raise ValueError("Feature values must be finite")

    global _model
    if _model is None:
        load_model()
    if _model is None:
        # Clearly a demo-only heuristic, not a trained or production detector.
        if values["unique_dst_ports"] >= 10 and values["syn_ratio"] >= 0.5:
            label, confidence = "port_scan", 0.75
        elif values["packets_per_second"] >= 1000 or values["bytes_per_second"] >= 1_000_000:
            label, confidence = "ddos", 0.75
        else:
            label, confidence = "normal", 0.75
    else:
        row = pd.DataFrame([[values[name] for name in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
        label = str(_model.predict(row)[0])
        probabilities = _model.predict_proba(row)[0]
        confidence = float(max(probabilities))
    return {
        "label": label,
        "confidence": round(confidence, 4),
        "severity": severity_from(label, confidence),
    }


if __name__ == "__main__":
    sample = {column: 0.0 for column in FEATURE_COLUMNS}
    print(predict(sample))
