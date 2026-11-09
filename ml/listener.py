"""TCP receiver for newline-delimited flow JSON from the C++ capture agent."""

import json
import logging
import os
import socket

from db.writer import get_connection, validate_flow, write_flow, write_threat_event
from ml import infer


LOG = logging.getLogger("argus.listener")
HOST = os.getenv("ARGUS_LISTENER_HOST", "0.0.0.0")
PORT = int(os.getenv("ARGUS_LISTENER_PORT", "9999"))
MODEL_PATH = os.getenv("ARGUS_MODEL_PATH", "model.joblib")
MAX_LINE_BYTES = int(os.getenv("ARGUS_MAX_FLOW_BYTES", "1048576"))


def handle_flow(flow: dict):
    """Validate, classify, and persist a flow; record threats above the configured threshold."""
    validate_flow(flow)
    verdict = infer.predict(flow["features"])
    with get_connection() as conn:
        write_flow(conn, flow)
        if verdict["label"] != "normal" and verdict["severity"] in {"MEDIUM", "HIGH"}:
            write_threat_event(conn, flow, verdict)
    LOG.info("processed flow %s: %s (%.4f)", flow["flow_id"], verdict["label"], verdict["confidence"])
    return verdict


def _process_line(line: bytes):
    if not line.strip():
        return
    try:
        flow = json.loads(line.decode("utf-8"))
        verdict = handle_flow(flow)
        LOG.debug("verdict for %s: %s", flow.get("flow_id"), verdict)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, KeyError) as exc:
        LOG.warning("discarding invalid flow payload: %s", exc)
    except Exception:
        LOG.exception("failed processing flow")


def serve(host: str = HOST, port: int = PORT):
    """Accept repeated agent connections and process newline-delimited JSON records."""
    model = infer.load_model(MODEL_PATH)
    if model is None:
        LOG.warning("no trained model found at %s; using demo-only heuristic classifier", MODEL_PATH)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()
        LOG.info("listening for capture agent on %s:%d", host, port)
        while True:
            conn, addr = server.accept()
            LOG.info("agent connected from %s:%d", *addr)
            with conn:
                buffer = bytearray()
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        if buffer:
                            _process_line(bytes(buffer))
                        break
                    buffer.extend(chunk)
                    if len(buffer) > MAX_LINE_BYTES and b"\n" not in buffer:
                        LOG.warning("dropping oversized flow line from %s", addr[0])
                        buffer.clear()
                        continue
                    while b"\n" in buffer:
                        line, _, rest = buffer.partition(b"\n")
                        buffer = bytearray(rest)
                        if len(line) > MAX_LINE_BYTES:
                            LOG.warning("dropping oversized flow line from %s", addr[0])
                            continue
                        _process_line(line)


def main():
    logging.basicConfig(level=os.getenv("ARGUS_LOG_LEVEL", "INFO"))
    serve()


if __name__ == "__main__":
    main()
