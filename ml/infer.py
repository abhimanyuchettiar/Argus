"""
Argus — inference wrapper.

Loads the trained model bundle (model + LabelEncoder saved by train.py)
and turns a flow-features dict (matching docs/FLOW_SCHEMA.md §3) into a
verdict dict (label, confidence, severity).

The model bundle is a dict saved with joblib:
  {"model": RandomForestClassifier, "label_encoder": LabelEncoder}

If no bundle exists yet (e.g. demo mode before training), the module raises
a clear error rather than silently returning garbage.
"""

import joblib
import numpy as np
import pandas as pd

from train import FEATURE_COLUMNS

# Module-level cache so we only load from disk once per process.
_bundle: dict | None = None


def load_model(path: str = "model.joblib") -> dict:
    """Load model bundle from disk and cache it. Returns the bundle dict."""
    global _bundle
    _bundle = joblib.load(path)
    # Support both the new bundle format and a bare sklearn model (legacy).
    if not isinstance(_bundle, dict):
        # Wrap a bare model so the rest of the code stays consistent.
        _bundle = {"model": _bundle, "label_encoder": None}
    return _bundle


def severity_from(label: str, confidence: float) -> str:
    """Derive severity string from label + confidence.
    Thresholds can be tuned once real traffic data is available.
    """
    if label == "normal":
        return "LOW"
    if confidence >= 0.9:
        return "HIGH"
    if confidence >= 0.6:
        return "MEDIUM"
    return "LOW"


def predict(features: dict, flow_id: str = "") -> dict:
    """
    Run inference on one flow.

    Args:
        features: dict matching the 'features' object in docs/FLOW_SCHEMA.md §3.
                  All 15 keys must be present.
        flow_id:  Optional flow identifier string for the returned verdict.

    Returns:
        dict matching the Verdict JSON object in docs/FLOW_SCHEMA.md §4:
          { "flow_id", "label", "confidence", "severity" }

    Raises:
        RuntimeError: if the model has not been loaded yet.
        KeyError:     if a required feature key is missing from `features`.
    """
    if _bundle is None:
        raise RuntimeError(
            "[infer] Model not loaded. Call load_model(path) first, "
            "or run 'python train.py' to create a model."
        )

    model = _bundle["model"]
    le    = _bundle.get("label_encoder")

    # Build a single-row DataFrame in the exact feature order.
    # This will raise KeyError if any of the 15 keys is missing — intentional.
    row = pd.DataFrame([features])[FEATURE_COLUMNS]

    raw_pred   = model.predict(row)[0]
    confidence = float(model.predict_proba(row).max())

    # Decode integer prediction if a LabelEncoder was saved.
    # Use isinstance() rather than np.issubdtype(type(...)) because the latter
    # returns False for plain Python int, which some sklearn versions may return.
    if le is not None and isinstance(raw_pred, (int, np.integer)):
        label = le.inverse_transform([raw_pred])[0]
    else:
        label = str(raw_pred)

    return {
        "flow_id":    flow_id,
        "label":      label,
        "confidence": round(confidence, 4),
        "severity":   severity_from(label, confidence),
    }


if __name__ == "__main__":
    import os

    MODEL_PATH = "model.joblib"
    if not os.path.exists(MODEL_PATH):
        print(
            f"[infer] No model found at '{MODEL_PATH}'.\n"
            "  Run 'python train.py --data <csv> --out model.joblib' first."
        )
    else:
        load_model(MODEL_PATH)
        # Quick smoke test with all-zero features (represents a near-idle flow).
        sample = {col: 0.0 for col in FEATURE_COLUMNS}
        result = predict(sample, flow_id="smoke-test")
        print("[infer] Smoke test result:", result)
