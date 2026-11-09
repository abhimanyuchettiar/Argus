"""Send harmless synthetic flow records to exercise the Argus pipeline."""

import json
import os
import socket
import time
from datetime import datetime, timezone

HOST = os.getenv("ARGUS_LISTENER_HOST", "listener")
PORT = int(os.getenv("ARGUS_LISTENER_PORT", "9999"))
INTERVAL = float(os.getenv("ARGUS_DEMO_INTERVAL", "2"))


def make_flow(index: int) -> dict:
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    features = {
        "packets_per_second": 12.0,
        "bytes_per_second": 8400.0,
        "avg_packet_size": 700.0,
        "syn_ratio": 0.1,
        "fin_ratio": 0.0,
        "unique_dst_ports": 1,
        "flow_duration_ms": 1000,
        "protocol_encoded": 0,
        "dst_port_val": 443,
        "payload_entropy": 3.5,
        "inter_arrival_mean": 0.08,
        "inter_arrival_std": 0.01,
        "psh_ratio": 0.1,
        "ack_ratio": 0.7,
        "rst_ratio": 0.0,
    }
    return {
        "flow_id": f"demo-{index}-10.0.0.5:50000-10.0.0.10:443-TCP",
        "timestamp": now,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.10",
        "src_port": 50000,
        "dst_port": 443,
        "protocol": 0,
        "features": features,
    }


def main():
    index = 0
    while True:
        try:
            with socket.create_connection((HOST, PORT), timeout=5) as connection:
                payload = (json.dumps(make_flow(index)) + "\n").encode("utf-8")
                connection.sendall(payload)
            print(f"sent synthetic demo flow {index}", flush=True)
            index += 1
            time.sleep(INTERVAL)
        except OSError as exc:
            print(f"listener connection failed: {exc}; retrying", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
