"""
Argus — Socket Listener & Real-Time ML Classification Pipeline.

Receives streaming flow JSON over TCP (from the C++ capture agent or replay test),
runs ML inference via infer.predict(), logs real-time verdicts, and optionally
persists flows/threats into TimescaleDB via db.writer.
"""

import argparse
import json
import logging
import os
import signal
import socket
import sys

# Ensure ml/ directory is importable
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import infer

# Optional DB integration
db_writer = None
try:
    from db import writer as db_writer
except Exception as exc:
    db_writer = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
LOG = logging.getLogger("argus.listener")

_db_conn = None
_db_attempted = False


def get_db_connection():
    """Lazily establish a database connection if db_writer is available."""
    global _db_conn, _db_attempted
    if _db_conn is not None:
        return _db_conn
    if _db_attempted or db_writer is None:
        return None

    _db_attempted = True
    try:
        _db_conn = db_writer.get_connection()
        LOG.info("[db] Connected to TimescaleDB successfully.")
        return _db_conn
    except Exception as exc:
        LOG.warning("[db] TimescaleDB unavailable (%s). Continuing in memory-only mode.", exc)
        return None


def handle_flow(flow: dict) -> dict | None:
    """Classify incoming flow features and record verdicts."""
    flow_id = flow.get("flow_id", "unknown")
    features = flow.get("features")
    if not features or not isinstance(features, dict):
        LOG.warning("Discarding malformed flow missing 'features': %s", flow_id)
        return None

    try:
        verdict = infer.predict(features, flow_id=flow_id)
    except Exception as exc:
        LOG.error("Inference failed for flow %s: %s", flow_id, exc)
        return None

    label = verdict.get("label", "unknown")
    confidence = verdict.get("confidence", 0.0)
    severity = verdict.get("severity", "LOW")

    if label != "normal" and severity in ("MEDIUM", "HIGH"):
        LOG.warning(
            "🚨 [THREAT DETECTED] %s | Type: %s | Severity: %s | Confidence: %.2f%%",
            flow_id, label.upper(), severity, confidence * 100
        )
    else:
        LOG.info("[FLOW OK] %s | %s (%.2f%%)", flow_id, label, confidence * 100)

    # Optional database persistence
    conn = get_db_connection()
    if conn:
        try:
            db_writer.write_flow(conn, flow)
            if label != "normal" and severity in ("MEDIUM", "HIGH"):
                db_writer.write_threat_event(conn, flow, verdict)
        except Exception as exc:
            LOG.error("Failed to write flow %s to database: %s", flow_id, exc)

    return verdict


def serve(host: str = "0.0.0.0", port: int = 9999, model_path: str = "model.joblib"):
    """Accept TCP connections and process newline-delimited JSON flow records."""
    if not os.path.exists(model_path):
        alt_path = os.path.join(CURRENT_DIR, model_path)
        if os.path.exists(alt_path):
            model_path = alt_path

    if not os.path.exists(model_path):
        LOG.error("Model file '%s' not found. Run training or generate model first.", model_path)
        sys.exit(1)

    LOG.info("Loading ML model from '%s'...", model_path)
    infer.load_model(model_path)
    LOG.info("ML model loaded successfully.")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    LOG.info("Argus Socket Listener running on %s:%d (waiting for agent or replayer)...", host, port)

    def shutdown_handler(signum, frame):
        LOG.info("Shutting down listener...")
        server.close()
        if _db_conn:
            try:
                _db_conn.close()
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    while True:
        try:
            conn, addr = server.accept()
            LOG.info("Connected to client: %s:%d", addr[0], addr[1])
        except (socket.error, OSError):
            break

        buffer = ""
        with conn:
            while True:
                try:
                    data = conn.recv(4096)
                except socket.error:
                    break
                if not data:
                    break

                buffer += data.decode("utf-8", errors="replace")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if line:
                        try:
                            flow_obj = json.loads(line)
                            handle_flow(flow_obj)
                        except json.JSONDecodeError as exc:
                            LOG.warning("Failed to decode JSON line: %s", exc)

            LOG.info("Client %s:%d disconnected.", addr[0], addr[1])


def main():
    parser = argparse.ArgumentParser(description="Argus ML Socket Listener")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9999, help="Listen port (default: 9999)")
    parser.add_argument("--model", default="model.joblib", help="Path to trained model bundle")
    args = parser.parse_args()

    serve(host=args.host, port=args.port, model_path=args.model)


if __name__ == "__main__":
    main()
