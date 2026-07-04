"""
Argus — database writer.

Inserts incoming flows (and their ML verdicts) into TimescaleDB.
Schema: see db/schema.sql. JSON shapes: see docs/FLOW_SCHEMA.md.
"""

import psycopg2

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "argus",
    "user": "postgres",
    "password": "",  # TODO: use an env var, don't commit real credentials
}


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def write_flow(conn, flow: dict):
    """flow: dict matching the Flow JSON object in docs/FLOW_SCHEMA.md"""
    f = flow["features"]
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
            {
                "timestamp": flow["timestamp"],
                "flow_id": flow["flow_id"],
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],
                "protocol": flow["protocol"],
                **f,
            },
        )
    conn.commit()


def write_threat_event(conn, flow: dict, verdict: dict):
    """verdict: dict matching the Verdict JSON object in docs/FLOW_SCHEMA.md"""
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


# TODO(week 4): add write_embedding() once flow_embeddings vectorization approach is decided.
