"""
Argus — synthetic fixture replayer.

Reads demo_flows.csv and sends each row to the running listener as
newline-delimited JSON, simulating what the C++ agent does over TCP.

⚠️  ALL DATA IN THIS SCRIPT IS SYNTHETIC — for pipeline testing only.
    Any predictions produced are DEMONSTRATION-ONLY and do not reflect
    real-world accuracy.

Usage (run AFTER starting ml/listener.py in another terminal):
    python ml/tests/replay_fixture.py [--host 127.0.0.1] [--port 9999]
"""

import argparse
import csv
import json
import os
import socket
import time

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "demo_flows.csv")

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


def build_flow_json(row: dict, idx: int) -> str:
    """Convert one CSV row into the Flow JSON format from docs/FLOW_SCHEMA.md."""
    label = row.get("label", "unknown")
    source = row.get("source", "SYNTHETIC")

    features = {}
    for col in FEATURE_COLUMNS:
        try:
            features[col] = float(row[col])
        except (KeyError, ValueError):
            features[col] = 0.0

    # Integer features
    for int_col in ("unique_dst_ports", "flow_duration_ms", "protocol_encoded", "dst_port_val"):
        features[int_col] = int(features[int_col])

    flow = {
        "flow_id":   f"SYNTHETIC-{idx:04d}-{label}",
        "timestamp": "2026-01-01T00:00:00.000Z",
        "src_ip":    "192.0.2.1",   # TEST-NET — RFC 5737
        "dst_ip":    "192.0.2.2",
        "src_port":  10000 + idx,
        "dst_port":  features["dst_port_val"],
        "protocol":  features["protocol_encoded"],
        "features":  features,
        # Extra metadata so the listener can log it:
        "_demo_label":  label,         # ground-truth label (SYNTHETIC)
        "_demo_source": source,        # always "SYNTHETIC"
        "_demo_note":   "[DEMO ONLY] Synthetic fixture — not real traffic",
    }
    return json.dumps(flow)


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay synthetic fixture to listener")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument(
        "--delay", type=float, default=0.1,
        help="Seconds between messages (default 0.1)"
    )
    args = parser.parse_args()

    print(
        "⚠️  [replay] ALL DATA IS SYNTHETIC — DEMONSTRATION ONLY\n"
        f"   Sending fixture: {FIXTURE_PATH}\n"
        f"   Target: {args.host}:{args.port}"
    )

    with open(FIXTURE_PATH, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    print(f"[replay] {len(rows)} flows to send.")

    with socket.create_connection((args.host, args.port)) as sock:
        for idx, row in enumerate(rows):
            msg = build_flow_json(row, idx) + "\n"
            sock.sendall(msg.encode("utf-8"))
            print(f"[replay] Sent flow {idx:04d}: label={row.get('label')}")
            time.sleep(args.delay)

    print("[replay] Done.")


if __name__ == "__main__":
    main()
