"""
Argus — API server.

Serves flow/threat data to the dashboard.
Week 7 goal: REST endpoints. Stretch: WebSocket for real-time push instead of polling.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Argus API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: tighten before any real deployment
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/flows")
def get_flows(minutes: int = 5):
    """Recent flows, last N minutes."""
    # TODO(week 7): query db.writer.get_connection(), SELECT from network_flows
    # WHERE time > now() - INTERVAL '%s minutes'.
    return {"minutes": minutes, "flows": []}


@app.get("/threats")
def get_threats(minutes: int = 5):
    """Recent classified threats."""
    # TODO(week 7): query threat_events table.
    return {"minutes": minutes, "threats": []}


@app.get("/stats")
def get_stats():
    """Summary stats for dashboard header: packets/sec, threat count, protocol breakdown."""
    # TODO(week 7): aggregate from network_flows / threat_events.
    return {"packets_per_second": 0, "active_threats": 0, "protocol_breakdown": {}}


# TODO(week 7 stretch): WebSocket endpoint at /ws that pushes new flows/threats
# as they're written, instead of the dashboard polling /flows and /threats every second.
