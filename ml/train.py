"""
Argus — model training script.

Week 5 goal: load CICIDS2017, engineer the 15 features (must match
docs/FLOW_SCHEMA.md exactly — same names, same order), train a baseline
Random Forest, then optionally an XGBoost model for comparison.

Usage:
    python3 train.py --data ../data/cicids2017.csv --out model.joblib
"""

import argparse

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Must match docs/FLOW_SCHEMA.md section 3 exactly — same names, same order.
FEATURE_COLUMNS = [
    "packets_per_second",
    "bytes_per_second",
    "avg_packet_size",
    "syn_ratio",
    "fin_ratio",
    "unique_dst_ports",
    "flow_duration_ms",
    "protocol_encoded",
    "dst_port_val",
    "payload_entropy",
    "inter_arrival_mean",
    "inter_arrival_std",
    "psh_ratio",
    "ack_ratio",
    "rst_ratio",
]

LABEL_COLUMN = "label"  # normal, port_scan, ddos, brute_force, dns_amplification, arp_spoof, exfiltration


def load_and_clean(path: str) -> pd.DataFrame:
    # TODO(week 5): load CICIDS2017 CSV, map its raw columns onto FEATURE_COLUMNS,
    # handle NaNs/infs (CICIDS2017 has some), and normalize the label column names.
    df = pd.read_csv(path)
    return df


def train(df: pd.DataFrame):
    X = df[FEATURE_COLUMNS]
    y = df[LABEL_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # TODO(week 5): also try XGBoost here and compare F1 scores.
    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    print(classification_report(y_test, preds))

    return model


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="Path to CICIDS2017 CSV")
    parser.add_argument("--out", default="model.joblib", help="Output model path")
    args = parser.parse_args()

    df = load_and_clean(args.data)
    model = train(df)
    joblib.dump(model, args.out)
    print(f"Model saved to {args.out}")


if __name__ == "__main__":
    main()
