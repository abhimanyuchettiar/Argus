"""
Argus — socket listener.

Receives flow JSON from the C++ agent over TCP (see docs/FLOW_SCHEMA.md),
runs inference, and passes the flow + verdict to the DB writer.

Week 3 goal: just receive and print the JSON.
Week 6 goal: wire in infer.py + db/writer.py for the full pipeline.
"""

import json
import socket

HOST = "0.0.0.0"
PORT = 9999


def handle_flow(flow: dict):
    # TODO(week 6): call infer.predict(flow["features"]), then
    # db.writer.write_flow(flow, verdict) if confidence crosses threshold.
    print("[listener] received flow:", flow.get("flow_id"))


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[listener] waiting for agent on {HOST}:{PORT}")

        conn, addr = server.accept()
        print(f"[listener] connected: {addr}")

        buffer = ""
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buffer += data.decode("utf-8")
                # TODO(week 3): agree on a framing scheme with the agent —
                # newline-delimited JSON is simplest, adjust sender.cpp to match.
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        handle_flow(json.loads(line))


if __name__ == "__main__":
    main()
