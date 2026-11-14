"""Argus REST API serving recent flows, threats, and summary statistics."""

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from db.writer import fetch_all


app = FastAPI(title="Argus API", version="1.0.0")
allowed_origins = [
    origin.strip()
    for origin in os.getenv("ARGUS_CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
    if origin.strip()
]
DASHBOARD_DIR = Path(__file__).resolve().parents[1] / "dashboard"
if DASHBOARD_DIR.is_dir():
    app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIR), name="dashboard-static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET"],
    allow_headers=["*"],
)


def _read(query: str, params=()):
    try:
        return fetch_all(query, params)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database unavailable or query failed") from exc


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(DASHBOARD_DIR / "index.html")


@app.get("/health")
def health():
    """Return service and database readiness."""
    _read("SELECT 1 AS ready")
    return {"status": "ok", "database": "ok"}


@app.get("/flows")
def get_flows(minutes: int = Query(default=5, ge=1, le=1440), limit: int = Query(default=500, ge=1, le=5000)):
    """Return recent flows, newest first."""
    flows = _read(
        """SELECT time AS timestamp, flow_id, src_ip::text AS src_ip, dst_ip::text AS dst_ip,
                  src_port, dst_port, protocol, packets_per_second, bytes_per_second,
                  avg_packet_size, syn_ratio, fin_ratio, unique_dst_ports, flow_duration_ms,
                  payload_entropy, inter_arrival_mean, inter_arrival_std, psh_ratio, ack_ratio, rst_ratio
           FROM network_flows WHERE time >= now() - (%s * INTERVAL '1 minute')
           ORDER BY time DESC LIMIT %s""",
        (minutes, limit),
    )
    return {"minutes": minutes, "flows": flows}


@app.get("/threats")
def get_threats(minutes: int = Query(default=5, ge=1, le=1440), limit: int = Query(default=500, ge=1, le=5000)):
    """Return recent classified threats, newest first."""
    threats = _read(
        """SELECT time AS timestamp, flow_id, src_ip::text AS src_ip, label, confidence, severity
           FROM threat_events WHERE time >= now() - (%s * INTERVAL '1 minute')
           ORDER BY time DESC LIMIT %s""",
        (minutes, limit),
    )
    return {"minutes": minutes, "threats": threats}


@app.get("/stats")
def get_stats():
    """Return recent packet-rate estimate, active threat count, and protocol distribution."""
    rows = _read(
        """SELECT COALESCE(SUM(packets_per_second), 0) AS packets_per_second
           FROM network_flows WHERE time >= now() - INTERVAL '1 minute'"""
    )
    threats = _read(
        """SELECT COUNT(*) AS active_threats FROM threat_events
           WHERE time >= now() - INTERVAL '5 minutes'"""
    )
    protocols = _read(
        """SELECT protocol, COUNT(*) AS flow_count FROM network_flows
           WHERE time >= now() - INTERVAL '5 minutes' GROUP BY protocol ORDER BY protocol"""
    )
    return {
        "packets_per_second": float(rows[0]["packets_per_second"]),
        "active_threats": int(threats[0]["active_threats"]),
        "protocol_breakdown": {str(row["protocol"]): int(row["flow_count"]) for row in protocols},
    }
