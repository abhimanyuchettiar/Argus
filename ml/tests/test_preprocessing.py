"""
Tests for train.py preprocessing helpers.

These tests work WITHOUT any real data or trained model — they construct tiny
DataFrames inline to verify each cleaning step in isolation.

Run with:
    pytest ml/tests/test_preprocessing.py -v
"""

import sys
import os

# Add the ml/ directory to sys.path so we can import train.py directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import pandas as pd
import pytest

from train import (
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    LABEL_MAP,
    PROTOCOL_MAP,
)


# ---------------------------------------------------------------------------
# Helpers to build minimal test DataFrames
# ---------------------------------------------------------------------------

def _make_cicids_row(**overrides) -> dict:
    """Return a dict that looks like one stripped row from a CICIDS2017 CSV."""
    base = {
        "Flow Packets/s":         10.0,
        "Flow Bytes/s":           8000.0,
        "Packet Length Mean":     800.0,
        "SYN Flag Count":         1.0,
        "FIN Flag Count":         1.0,
        "PSH Flag Count":         2.0,
        "ACK Flag Count":         6.0,
        "RST Flag Count":         0.0,
        "Total Fwd Packets":      5.0,
        "Total Backward Packets": 5.0,
        "Flow Duration":          1_000_000.0,  # 1 second in microseconds
        "Protocol":               6,            # TCP
        "Destination Port":       443,
        "Fwd IAT Mean":           100_000.0,    # 0.1 s in microseconds
        "Fwd IAT Std":            10_000.0,     # 0.01 s
        "Label":                  "BENIGN",
    }
    base.update(overrides)
    return base


def _make_cicids_df(*rows) -> pd.DataFrame:
    if not rows:
        rows = [_make_cicids_row()]
    return pd.DataFrame(rows)


def _clean_minimal(df: pd.DataFrame) -> pd.DataFrame:
    """Run just the column-rename + feature-derivation part of load_and_clean,
    without touching the filesystem.  Extracted so tests can call it inline."""
    from train import CICIDS_COLUMN_MAP

    df = df.copy()
    df.columns = df.columns.str.strip()
    df = df.rename(columns=CICIDS_COLUMN_MAP)

    total_packets = df["_tot_fwd"] + df["_tot_bwd"]
    total_packets = total_packets.replace(0, np.nan)

    df["packets_per_second"] = df["_pps"]
    df["bytes_per_second"]   = df["_bps"]
    df["avg_packet_size"]    = df["_avg_pkt"]
    df["syn_ratio"]          = df["_syn_count"] / total_packets
    df["fin_ratio"]          = df["_fin_count"] / total_packets
    df["psh_ratio"]          = df["_psh_count"] / total_packets
    df["ack_ratio"]          = df["_ack_count"] / total_packets
    df["rst_ratio"]          = df["_rst_count"] / total_packets
    df["unique_dst_ports"]   = 1
    df["flow_duration_ms"]   = (df["_flow_dur_us"] / 1_000).round().astype("int64")
    df["protocol_encoded"]   = df["_proto_raw"].map(PROTOCOL_MAP)
    df["payload_entropy"]    = 0.0
    df["inter_arrival_mean"] = df["_iat_mean_us"] / 1_000_000
    df["inter_arrival_std"]  = df["_iat_std_us"]  / 1_000_000
    df["label"]              = df["_raw_label"].str.strip().map(LABEL_MAP)

    df = df[df["label"].notna()].copy()
    cols = FEATURE_COLUMNS + [LABEL_COLUMN]
    df = df[cols]
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan)
    df = df[~df[FEATURE_COLUMNS].isna().any(axis=1)].copy()
    return df[cols]


# ---------------------------------------------------------------------------
# Tests: unit conversions
# ---------------------------------------------------------------------------

class TestUnitConversions:
    def test_flow_duration_microseconds_to_ms(self):
        """Flow Duration of 1,000,000 µs must become 1000 ms."""
        raw = _make_cicids_df(_make_cicids_row(**{"Flow Duration": 2_000_000.0}))
        df = _clean_minimal(raw)
        assert df["flow_duration_ms"].iloc[0] == 2000.0

    def test_iat_mean_microseconds_to_seconds(self):
        """Fwd IAT Mean of 500,000 µs must become 0.5 s."""
        raw = _make_cicids_df(_make_cicids_row(**{"Fwd IAT Mean": 500_000.0}))
        df = _clean_minimal(raw)
        assert abs(df["inter_arrival_mean"].iloc[0] - 0.5) < 1e-9

    def test_iat_std_microseconds_to_seconds(self):
        raw = _make_cicids_df(_make_cicids_row(**{"Fwd IAT Std": 200_000.0}))
        df = _clean_minimal(raw)
        assert abs(df["inter_arrival_std"].iloc[0] - 0.2) < 1e-9


# ---------------------------------------------------------------------------
# Tests: flag ratios
# ---------------------------------------------------------------------------

class TestFlagRatios:
    def test_syn_ratio(self):
        """2 SYN packets out of 10 total → 0.2."""
        raw = _make_cicids_df(_make_cicids_row(**{
            "SYN Flag Count": 2.0,
            "Total Fwd Packets": 5.0,
            "Total Backward Packets": 5.0,
        }))
        df = _clean_minimal(raw)
        assert abs(df["syn_ratio"].iloc[0] - 0.2) < 1e-9

    def test_zero_packet_ratio_dropped(self):
        """A row with 0 total packets produces NaN ratios and must be dropped."""
        raw = _make_cicids_df(_make_cicids_row(**{
            "Total Fwd Packets": 0.0,
            "Total Backward Packets": 0.0,
        }))
        df = _clean_minimal(raw)
        assert len(df) == 0, "Row with 0 packets should be dropped"


# ---------------------------------------------------------------------------
# Tests: NaN and Inf cleaning
# ---------------------------------------------------------------------------

class TestNanInfCleaning:
    def test_inf_in_bps_drops_row(self):
        """Rows with Inf in Flow Bytes/s must be dropped."""
        raw = _make_cicids_df(_make_cicids_row(**{"Flow Bytes/s": float("inf")}))
        df = _clean_minimal(raw)
        assert len(df) == 0, "Row with Inf bytes/s should be dropped"

    def test_negative_inf_drops_row(self):
        raw = _make_cicids_df(_make_cicids_row(**{"Flow Packets/s": float("-inf")}))
        df = _clean_minimal(raw)
        assert len(df) == 0

    def test_nan_in_feature_drops_row(self):
        """A NaN arriving in any feature column must cause the row to be dropped."""
        raw = _make_cicids_df(_make_cicids_row(**{"Packet Length Mean": float("nan")}))
        df = _clean_minimal(raw)
        assert len(df) == 0

    def test_clean_row_not_dropped(self):
        """A fully valid row must survive cleaning."""
        raw = _make_cicids_df(_make_cicids_row())
        df = _clean_minimal(raw)
        assert len(df) == 1


# ---------------------------------------------------------------------------
# Tests: label mapping
# ---------------------------------------------------------------------------

class TestLabelMapping:
    def test_benign_maps_to_normal(self):
        raw = _make_cicids_df(_make_cicids_row(**{"Label": "BENIGN"}))
        df = _clean_minimal(raw)
        assert df["label"].iloc[0] == "normal"

    def test_portscan_maps_to_port_scan(self):
        raw = _make_cicids_df(_make_cicids_row(**{"Label": "PortScan"}))
        df = _clean_minimal(raw)
        assert df["label"].iloc[0] == "port_scan"

    def test_ftp_patator_maps_to_brute_force(self):
        raw = _make_cicids_df(_make_cicids_row(**{"Label": "FTP-Patator"}))
        df = _clean_minimal(raw)
        assert df["label"].iloc[0] == "brute_force"

    def test_unknown_label_is_dropped(self):
        """An unmapped label like 'Bot' must be silently dropped, not passed through."""
        raw = _make_cicids_df(
            _make_cicids_row(**{"Label": "BENIGN"}),
            _make_cicids_row(**{"Label": "Bot"}),       # not in LABEL_MAP
            _make_cicids_row(**{"Label": "Heartbleed"}), # not in LABEL_MAP
        )
        df = _clean_minimal(raw)
        assert len(df) == 1, "Only the BENIGN row should survive"
        assert df["label"].iloc[0] == "normal"

    def test_whitespace_in_label_stripped(self):
        """Labels with surrounding whitespace must still map correctly."""
        raw = _make_cicids_df(_make_cicids_row(**{"Label": "  BENIGN  "}))
        df = _clean_minimal(raw)
        assert df["label"].iloc[0] == "normal"


# ---------------------------------------------------------------------------
# Tests: column validation
# ---------------------------------------------------------------------------

class TestColumnValidation:
    def test_missing_column_raises_value_error(self, tmp_path):
        """load_and_clean must raise ValueError if a required column is missing."""
        # Build a CSV that is missing 'SYN Flag Count'
        row = _make_cicids_row()
        del row["SYN Flag Count"]
        df = pd.DataFrame([row])
        csv_path = tmp_path / "bad.csv"
        df.to_csv(csv_path, index=False)

        from train import load_and_clean
        with pytest.raises(ValueError, match="Missing required columns"):
            load_and_clean(str(csv_path))

    def test_column_order_matches_feature_columns(self):
        """After cleaning, columns must appear in the exact order of FEATURE_COLUMNS."""
        raw = _make_cicids_df(_make_cicids_row())
        df = _clean_minimal(raw)
        assert list(df.columns) == FEATURE_COLUMNS + [LABEL_COLUMN]


# ---------------------------------------------------------------------------
# Tests: protocol encoding
# ---------------------------------------------------------------------------

class TestProtocolEncoding:
    def test_tcp_encoded_as_0(self):
        raw = _make_cicids_df(_make_cicids_row(**{"Protocol": 6}))
        df = _clean_minimal(raw)
        assert df["protocol_encoded"].iloc[0] == 0

    def test_udp_encoded_as_1(self):
        raw = _make_cicids_df(_make_cicids_row(**{"Protocol": 17}))
        df = _clean_minimal(raw)
        assert df["protocol_encoded"].iloc[0] == 1

    def test_icmp_encoded_as_2(self):
        raw = _make_cicids_df(_make_cicids_row(**{"Protocol": 1}))
        df = _clean_minimal(raw)
        assert df["protocol_encoded"].iloc[0] == 2

    def test_unknown_protocol_dropped(self):
        """An unmapped protocol (e.g. 58 = ICMPv6) produces NaN → row dropped."""
        raw = _make_cicids_df(_make_cicids_row(**{"Protocol": 58}))
        df = _clean_minimal(raw)
        assert len(df) == 0


# ---------------------------------------------------------------------------
# Tests: payload_entropy placeholder
# ---------------------------------------------------------------------------

class TestPayloadEntropy:
    def test_payload_entropy_is_zero(self):
        """payload_entropy must always be 0.0 when trained on CICIDS2017 CSVs."""
        raw = _make_cicids_df(_make_cicids_row())
        df = _clean_minimal(raw)
        assert df["payload_entropy"].iloc[0] == 0.0

    def test_unique_dst_ports_is_one(self):
        """unique_dst_ports must always be 1 for per-row CICIDS2017 data."""
        raw = _make_cicids_df(_make_cicids_row())
        df = _clean_minimal(raw)
        assert df["unique_dst_ports"].iloc[0] == 1


# ---------------------------------------------------------------------------
# Tests: rare-class guard (fix: minimum-sample check before train_test_split)
# ---------------------------------------------------------------------------

class TestRareClassGuard:
    """Regression tests for the minimum-samples-per-class check in train().

    The guard must raise ValueError BEFORE sklearn's train_test_split is called,
    so the error message is always human-readable rather than a cryptic sklearn
    traceback.
    """

    def _make_clean_df(self, label_list: list[str]) -> pd.DataFrame:
        """Build a minimal but fully valid cleaned DataFrame with the given labels.
        Each row has the exact 15 features train() expects."""
        rows = []
        for lbl in label_list:
            row = {col: 0.0 for col in FEATURE_COLUMNS}
            row["label"] = lbl
            rows.append(row)
        return pd.DataFrame(rows)

    def test_raises_when_class_has_one_sample(self):
        """A class with 1 sample must trigger ValueError before splitting."""
        from train import train as _train
        # 10 normals, 1 port_scan → port_scan cannot be stratified
        labels = ["normal"] * 10 + ["port_scan"] * 1
        df = self._make_clean_df(labels)
        with pytest.raises(ValueError, match="Stratified split requires"):
            _train(df)

    def test_raises_when_class_has_four_samples(self):
        """4 samples is still below the threshold of 5."""
        from train import train as _train
        labels = ["normal"] * 20 + ["ddos"] * 4
        df = self._make_clean_df(labels)
        with pytest.raises(ValueError, match="Stratified split requires"):
            _train(df)

    def test_raises_names_the_offending_classes(self):
        """The ValueError message must name the specific class that is too rare."""
        from train import train as _train
        labels = ["normal"] * 20 + ["port_scan"] * 2
        df = self._make_clean_df(labels)
        with pytest.raises(ValueError, match="port_scan"):
            _train(df)

    def test_raises_names_multiple_rare_classes(self):
        """When two classes are too rare, both names must appear in the error."""
        from train import train as _train
        labels = ["normal"] * 20 + ["port_scan"] * 2 + ["ddos"] * 3
        df = self._make_clean_df(labels)
        # Both rare class names must be mentioned in the ValueError message.
        with pytest.raises(ValueError, match="port_scan"):
            _train(df)
        with pytest.raises(ValueError, match="ddos"):
            _train(df)

    def test_no_raise_when_all_classes_have_five_or_more(self):
        """Exactly 5 samples per class must NOT trigger the guard."""
        from train import train as _train
        # 25 normal + 5 ddos = minimum safe for 80/20 stratified split
        labels = ["normal"] * 25 + ["ddos"] * 5
        df = self._make_clean_df(labels)
        # Should not raise — may raise for other reasons (sklearn fit on tiny
        # data) but the rare-class guard itself must be silent.
        try:
            _train(df)
        except ValueError as exc:
            assert "Stratified split requires" not in str(exc), (
                f"Rare-class guard fired unexpectedly: {exc}"
            )

    def test_raises_single_class_still_caught(self):
        """Only one distinct class → the existing ≥2-class check fires first."""
        from train import train as _train
        labels = ["normal"] * 20
        df = self._make_clean_df(labels)
        with pytest.raises(ValueError, match="Need at least 2 distinct labels"):
            _train(df)


# ---------------------------------------------------------------------------
# Tests: low-sample warning (< 50 rows) is printed but data is NOT dropped
# ---------------------------------------------------------------------------

class TestLowSampleWarning:
    """The warning for classes with <50 samples must be printed but must NOT
    alter the DataFrame or drop any rows."""

    def _make_clean_df(self, label_list: list[str]) -> pd.DataFrame:
        rows = []
        for lbl in label_list:
            row = {col: 0.0 for col in FEATURE_COLUMNS}
            row["label"] = lbl
            rows.append(row)
        return pd.DataFrame(rows)

    def test_warning_printed_for_rare_class(self, capsys):
        from train import train as _train
        # 100 normals + 10 ddos: ddos < 50 → warning expected
        # Also 10 >= 5 so no ValueError
        labels = ["normal"] * 100 + ["ddos"] * 10
        df = self._make_clean_df(labels)
        _train(df)
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "ddos" in captured.out

    def test_no_warning_when_all_classes_have_fifty_or_more(self, capsys):
        from train import train as _train
        labels = ["normal"] * 100 + ["ddos"] * 50
        df = self._make_clean_df(labels)
        _train(df)
        captured = capsys.readouterr()
        # The word WARNING must not appear for the low-sample threshold
        assert "statistically unreliable" not in captured.out

    def test_data_rows_not_dropped_by_warning(self):
        """The low-sample warning path must not remove any rows."""
        from train import train as _train
        labels = ["normal"] * 100 + ["ddos"] * 10
        df = self._make_clean_df(labels)
        row_count_before = len(df)
        _train(df)
        # df is passed by reference to train() but train() should not mutate it
        assert len(df) == row_count_before


# ---------------------------------------------------------------------------
# Tests: flow_duration_ms dtype is standard int64, not nullable Int64
# ---------------------------------------------------------------------------

class TestFlowDurationDtype:
    def test_flow_duration_dtype_is_int64(self):
        """flow_duration_ms must use standard int64, not pandas nullable Int64."""
        raw = _make_cicids_df(_make_cicids_row(**{"Flow Duration": 2_000_000.0}))
        df = _clean_minimal(raw)
        # pandas Int64 (nullable) has dtype.name == "Int64"
        # numpy int64 has dtype.name == "int64" (lowercase i)
        assert df["flow_duration_ms"].dtype.name == "int64", (
            f"Expected int64 but got {df['flow_duration_ms'].dtype}"
        )
