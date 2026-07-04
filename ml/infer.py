"""
Argus — inference wrapper.

Loads the trained model and turns a flow-features dict (matching
docs/FLOW_SCHEMA.md) into a verdict dict (label, confidence, severity).
"""

import joblib
import pandas as pd

from train import FEATURE_COLUMNS

_model = None


def load_model(path: str = "model.joblib"):
    global _model
    _model = joblib.load(path)
    return _model


def severity_from(label: str, confidence: float) -> str:
    # TODO(week 6): tune these thresholds against real demo traffic.
    if label == "normal":
        return "LOW"
    if confidence >= 0.9:
        return "HIGH"
    if confidence >= 0.6:
        return "MEDIUM"
    return "LOW"


def predict(features: dict) -> dict:
    """
    features: dict matching the "features" object in docs/FLOW_SCHEMA.md
    returns: dict matching the Verdict JSON object in docs/FLOW_SCHEMA.md
    """
    if _model is None:
        load_model()

    row = pd.DataFrame([features])[FEATURE_COLUMNS]
    label = _model.predict(row)[0]
    confidence = float(_model.predict_proba(row).max())

    return {
        "label": label,
        "confidence": round(confidence, 4),
        "severity": severity_from(label, confidence),
    }


if __name__ == "__main__":
    # Quick manual test — replace with a real sample from the agent once week 3 is done.
    sample = {col: 0.0 for col in FEATURE_COLUMNS}
    print(predict(sample))
