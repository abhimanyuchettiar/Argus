"""
Tests for infer.py — inference wrapper.

These tests do NOT require a trained model file on disk.
They use sklearn's DummyClassifier to create a tiny in-memory model bundle
that mirrors the format train.py produces, so the full predict() code path
is exercised without any real training data.

Run with:
    pytest ml/tests/test_infer.py -v
"""

import sys
import os

# Add ml/ to sys.path so we can import infer.py and train.py directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import joblib
import pytest

from sklearn.dummy import DummyClassifier
from sklearn.preprocessing import LabelEncoder

from train import FEATURE_COLUMNS


# ---------------------------------------------------------------------------
# Fixture: create a tiny DummyClassifier bundle in a temp directory
# ---------------------------------------------------------------------------

@pytest.fixture()
def dummy_model_path(tmp_path):
    """Create a model.joblib bundle identical in structure to what train.py saves,
    using DummyClassifier so no real training is needed."""
    le = LabelEncoder()
    # Fit on the 5 classes representable in CICIDS2017
    le.fit(["normal", "port_scan", "ddos", "brute_force", "exfiltration"])

    # DummyClassifier always predicts the most frequent class.
    # We give it two classes so predict_proba works.
    clf = DummyClassifier(strategy="most_frequent")
    X_dummy = np.zeros((6, len(FEATURE_COLUMNS)))
    y_dummy = le.transform(["normal", "normal", "ddos", "port_scan", "brute_force", "exfiltration"])
    clf.fit(X_dummy, y_dummy)

    bundle = {"model": clf, "label_encoder": le}
    path = tmp_path / "model.joblib"
    joblib.dump(bundle, path)
    return str(path)


@pytest.fixture(autouse=True)
def reset_bundle():
    """Reset the module-level _bundle cache between tests."""
    import infer
    infer._bundle = None
    yield
    infer._bundle = None


# ---------------------------------------------------------------------------
# Helper: build a valid features dict
# ---------------------------------------------------------------------------

def _sample_features(**overrides) -> dict:
    base = {col: 0.0 for col in FEATURE_COLUMNS}
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Tests: model loading
# ---------------------------------------------------------------------------

class TestModelLoading:
    def test_load_model_sets_bundle(self, dummy_model_path):
        import infer
        bundle = infer.load_model(dummy_model_path)
        assert "model" in bundle
        assert "label_encoder" in bundle

    def test_predict_before_load_raises(self):
        import infer
        with pytest.raises(RuntimeError, match="Model not loaded"):
            infer.predict(_sample_features())

    def test_missing_model_file_raises(self, tmp_path):
        import infer
        with pytest.raises(Exception):
            infer.load_model(str(tmp_path / "nonexistent.joblib"))


# ---------------------------------------------------------------------------
# Tests: predict() return shape and types
# ---------------------------------------------------------------------------

class TestPredictOutput:
    def test_returns_required_keys(self, dummy_model_path):
        import infer
        infer.load_model(dummy_model_path)
        result = infer.predict(_sample_features())
        assert set(result.keys()) == {"flow_id", "label", "confidence", "severity"}

    def test_flow_id_passthrough(self, dummy_model_path):
        import infer
        infer.load_model(dummy_model_path)
        result = infer.predict(_sample_features(), flow_id="test-flow-001")
        assert result["flow_id"] == "test-flow-001"

    def test_confidence_between_0_and_1(self, dummy_model_path):
        import infer
        infer.load_model(dummy_model_path)
        result = infer.predict(_sample_features())
        assert 0.0 <= result["confidence"] <= 1.0

    def test_label_is_string(self, dummy_model_path):
        import infer
        infer.load_model(dummy_model_path)
        result = infer.predict(_sample_features())
        assert isinstance(result["label"], str)

    def test_severity_valid_values(self, dummy_model_path):
        import infer
        infer.load_model(dummy_model_path)
        result = infer.predict(_sample_features())
        assert result["severity"] in ("LOW", "MEDIUM", "HIGH")

    def test_confidence_rounded_to_4dp(self, dummy_model_path):
        import infer
        infer.load_model(dummy_model_path)
        result = infer.predict(_sample_features())
        # Rounded to 4 decimal places means at most 4 digits after the decimal
        conf_str = str(result["confidence"])
        if "." in conf_str:
            assert len(conf_str.split(".")[1]) <= 4

    def test_missing_feature_key_raises(self, dummy_model_path):
        """If a caller omits one of the 15 feature keys, predict() must raise KeyError."""
        import infer
        infer.load_model(dummy_model_path)
        incomplete = _sample_features()
        del incomplete["syn_ratio"]    # remove one key
        with pytest.raises(KeyError):
            infer.predict(incomplete)


# ---------------------------------------------------------------------------
# Tests: severity_from() logic
# ---------------------------------------------------------------------------

class TestSeverityFrom:
    def test_normal_always_low(self):
        from infer import severity_from
        assert severity_from("normal", 0.99) == "LOW"
        assert severity_from("normal", 0.0)  == "LOW"

    def test_attack_high_confidence(self):
        from infer import severity_from
        assert severity_from("ddos", 0.95) == "HIGH"
        assert severity_from("port_scan", 0.90) == "HIGH"

    def test_attack_medium_confidence(self):
        from infer import severity_from
        assert severity_from("ddos", 0.75) == "MEDIUM"
        assert severity_from("brute_force", 0.60) == "MEDIUM"

    def test_attack_low_confidence(self):
        from infer import severity_from
        assert severity_from("ddos", 0.30) == "LOW"
        assert severity_from("exfiltration", 0.0) == "LOW"

    def test_boundary_exactly_0_9_is_high(self):
        from infer import severity_from
        assert severity_from("ddos", 0.9) == "HIGH"

    def test_boundary_exactly_0_6_is_medium(self):
        from infer import severity_from
        assert severity_from("ddos", 0.6) == "MEDIUM"

    def test_just_below_0_6_is_low(self):
        from infer import severity_from
        assert severity_from("ddos", 0.599) == "LOW"


# ---------------------------------------------------------------------------
# Tests: integer label decoding — isinstance fix (fix #5)
# ---------------------------------------------------------------------------

class TestLabelDecoding:
    """Regression tests for the isinstance-based label decoding in predict().

    Before the fix, np.issubdtype(type(raw_pred), np.integer) returned False
    for plain Python int, causing the fallback str(raw_pred) branch to fire
    and return "0" instead of a human-readable label string.
    """

    @pytest.fixture()
    def bundle_with_le(self, tmp_path):
        """Bundle where LabelEncoder maps integer 0 → 'normal', 1 → 'ddos'."""
        le = LabelEncoder()
        le.fit(["ddos", "normal"])   # alphabetical → ddos=0, normal=1

        clf = DummyClassifier(strategy="most_frequent")
        X_dummy = np.zeros((4, len(FEATURE_COLUMNS)))
        y_dummy = le.transform(["normal", "normal", "normal", "ddos"])
        clf.fit(X_dummy, y_dummy)

        bundle = {"model": clf, "label_encoder": le}
        path = tmp_path / "le_model.joblib"
        joblib.dump(bundle, path)
        return str(path), le

    def test_numpy_int_decoded_to_label_string(self, bundle_with_le):
        """A numpy.int64 prediction must be decoded via LabelEncoder, not str()."""
        import infer
        path, le = bundle_with_le
        infer.load_model(path)
        result = infer.predict(_sample_features())
        # The label must be a human-readable string from le.classes_, not "0" or "1"
        assert result["label"] in list(le.classes_), (
            f"Expected a label name, got: {result['label']!r}"
        )
        assert result["label"] != "0", "numpy int prediction was not decoded by LabelEncoder"
        assert result["label"] != "1", "numpy int prediction was not decoded by LabelEncoder"

    def test_plain_python_int_decoded_to_label_string(self, tmp_path, bundle_with_le):
        """A plain Python int prediction must also be decoded correctly.

        This tests the isinstance() fix: the old np.issubdtype(type(int), np.integer)
        returned False for Python int on some numpy versions.
        """
        import infer

        # Patch a bundle whose model.predict returns a plain Python int
        class _PythonIntModel:
            """Stub model that always returns Python int 1 from predict()."""
            def predict(self, X):
                return [1]   # plain Python int, not numpy
            def predict_proba(self, X):
                return np.array([[0.1, 0.9]])

        _, le = bundle_with_le
        infer._bundle = {"model": _PythonIntModel(), "label_encoder": le}

        result = infer.predict(_sample_features())
        # 1 → le.classes_[1] which is "normal" (alphabetical: ddos=0, normal=1)
        assert result["label"] == "normal", (
            f"Plain Python int was not decoded via LabelEncoder. Got: {result['label']!r}"
        )

    def test_label_without_encoder_returns_string(self, tmp_path):
        """When no LabelEncoder is present, the raw prediction is cast to str."""
        import infer

        class _StringModel:
            """Stub model that returns a string label directly."""
            def predict(self, X):
                return ["ddos"]
            def predict_proba(self, X):
                return np.array([[0.05, 0.95]])

        infer._bundle = {"model": _StringModel(), "label_encoder": None}
        result = infer.predict(_sample_features())
        assert result["label"] == "ddos"
        assert isinstance(result["label"], str)


# ---------------------------------------------------------------------------
# Tests: confusion matrix label ordering (fix #3)
# ---------------------------------------------------------------------------

class TestConfusionMatrixLabelOrder:
    """Verify that train() produces a confusion matrix whose dimensions and
    axis order always match le.classes_, even when a class appears only in
    predictions and not in the test ground-truth (or vice versa).

    We test this by inspecting the output of confusion_matrix() directly with
    the same arguments that train() now uses.
    """

    def test_pinned_labels_produce_square_matrix(self):
        """confusion_matrix with labels=list(range(n)) must give an n×n matrix."""
        from sklearn.metrics import confusion_matrix
        from sklearn.preprocessing import LabelEncoder

        le = LabelEncoder()
        le.fit(["brute_force", "ddos", "normal"])   # 3 classes → sorted alphabetical
        n = len(le.classes_)

        # y_test has only 2 of the 3 classes; preds has all 3
        y_test  = le.transform(["normal", "normal", "ddos"])
        y_preds = le.transform(["normal", "brute_force", "ddos"])

        cm = confusion_matrix(y_test, y_preds, labels=list(range(n)))
        assert cm.shape == (n, n), (
            f"Expected {n}×{n} matrix but got {cm.shape}"
        )

    def test_pinned_labels_row_count_matches_class_count(self):
        """Number of rows in the matrix must equal number of classes in le."""
        from sklearn.metrics import confusion_matrix
        from sklearn.preprocessing import LabelEncoder

        le = LabelEncoder()
        le.fit(["brute_force", "ddos", "exfiltration", "normal", "port_scan"])
        n = len(le.classes_)

        y_test  = le.transform(["normal", "ddos", "normal", "port_scan", "normal"])
        y_preds = le.transform(["normal", "ddos", "ddos",   "port_scan", "normal"])

        cm = confusion_matrix(y_test, y_preds, labels=list(range(n)))
        assert cm.shape[0] == n
        assert cm.shape[1] == n

    def test_unpinned_labels_can_mismatch(self):
        """Negative control: without labels=, shape depends on values present.
        This documents WHY the fix was needed."""
        from sklearn.metrics import confusion_matrix
        from sklearn.preprocessing import LabelEncoder

        le = LabelEncoder()
        le.fit(["brute_force", "ddos", "normal"])
        n = len(le.classes_)   # 3

        # y_test only contains class 1 and 2 (no brute_force in test set)
        y_test  = le.transform(["normal", "ddos"])
        y_preds = le.transform(["normal", "ddos"])

        cm_unpinned = confusion_matrix(y_test, y_preds)
        # Without labels=, shape is (unique values in y_test ∪ y_preds) = 2×2
        # This would NOT match le.classes_ which has 3 entries
        assert cm_unpinned.shape == (2, 2)

        # With labels= pinned, shape is always 3×3
        cm_pinned = confusion_matrix(y_test, y_preds, labels=list(range(n)))
        assert cm_pinned.shape == (3, 3)
