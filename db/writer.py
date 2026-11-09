"""Database access and writes for Argus flow and threat records."""

import os

import psycopg2
from psycopg2.extras import RealDictCursor


DB_CONFIG = {
    "host": os.getenv("ARGUS_DB_HOST", "localhost"),
    "port": int(os.getenv("ARGUS_DB_PORT", "5432")),
    "dbname": os.getenv("ARGUS_DB_NAME", "argus"),
    "user": os.getenv("ARGUS_DB_USER", "postgres"),
    "password": os.getenv("ARGUS_DB_PASSWORD", ""),
    "connect_timeout": int(os.getenv("ARGUS_DB_CONNECT_TIMEOUT", "5")),
}

FEATURE_COLUMNS = (
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
)
FLOW_COLUMNS = ("flow_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "features")


def get_connection():
    """Open a PostgreSQL connection using ARGUS_DB_* environment settings."""
    return psycopg2.connect(**DB_CONFIG)


def validate_flow(flow: dict) -> dict:
    """Check the outer flow and exact feature shape required by the data contract."""
    if not isinstance(flow, dict):
        raise ValueError("Flow payload must be a JSON object")
    missing = [key for key in FLOW_COLUMNS if key not in flow]
    if missing:
        raise ValueError(f"Flow is missing required fields: {', '.join(missing)}")
    if not isinstance(flow["features"], dict):
        raise ValueError("Flow features must be a JSON object")
    missing_features = [key for key in FEATURE_COLUMNS if key not in flow["features"]]
    extra_features = [key for key in flow["features"] if key not in FEATURE_COLUMNS]
    if missing_features or extra_features:
        details = []
        if missing_features:
            details.append(f"missing: {', '.join(missing_features)}")
        if extra_features:
            details.append(f"unexpected: {', '.join(extra_features)}")
        raise ValueError("Invalid feature fields (" + "; ".join(details) + ")")
    return flow


def write_flow(conn, flow: dict):
    """Insert one flow matching docs/FLOW_SCHEMA.md."""
    validate_flow(flow)
    features = flow["features"]
    values = {
        "timestamp": flow["timestamp"],
        "flow_id": flow["flow_id"],
        "src_ip": flow["src_ip"],
        "dst_ip": flow["dst_ip"],
        "src_port": flow["src_port"],
        "dst_port": flow["dst_port"],
        "protocol": flow["protocol"],
        **features,
    }
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO network_flows (
                time, flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                packets_per_second, bytes_per_second, avg_packet_size,
                syn_ratio, fin_ratio, unique_dst_ports, flow_duration_ms,
                payload_entropy, inter_arrival_mean, inter_arrival_std,
                psh_ratio, ack_ratio, rst_ratio
            ) VALUES (
                %(timestamp)s, %(flow_id)s, %(src_ip)s, %(dst_ip)s, %(src_port)s,
                %(dst_port)s, %(protocol)s, %(packets_per_second)s, %(bytes_per_second)s,
                %(avg_packet_size)s, %(syn_ratio)s, %(fin_ratio)s, %(unique_dst_ports)s,
                %(flow_duration_ms)s, %(payload_entropy)s, %(inter_arrival_mean)s,
                %(inter_arrival_std)s, %(psh_ratio)s, %(ack_ratio)s, %(rst_ratio)s
            )
            """,
            values,
        )
    conn.commit()


def write_threat_event(conn, flow: dict, verdict: dict):
    """Insert one classified threat."""
    required = {"label", "confidence", "severity"}
    if not isinstance(verdict, dict) or not required.issubset(verdict):
        raise ValueError("Verdict requires label, confidence, and severity")
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO threat_events (time, flow_id, src_ip, label, confidence, severity)
            VALUES (%(timestamp)s, %(flow_id)s, %(src_ip)s, %(label)s, %(confidence)s, %(severity)s)
            """,
            {
                "timestamp": flow["timestamp"],
                "flow_id": flow["flow_id"],
                "src_ip": flow["src_ip"],
                **verdict,
            },
        )
    conn.commit()


def fetch_all(query: str, params=()):
    """Run a read-only query and return rows as dictionaries."""
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]
