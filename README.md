# Argus — Real-Time Network Threat Detection System

Argus is a real-time network intrusion detection system (NIDS). It captures live traffic,
classifies it with a trained ML model, persists events in a time-series database, and renders
threats on a live dashboard. Every layer is built from scratch — no black-box detection
services.

Built for a CS Engineering course project, 8-week build plan, 3-person team.

## Architecture

```
┌──────────────────┐        TCP socket        ┌─────────────────────────────┐
│   Linux VM (UTM)  │  ──── flow JSON ──────▶  │         Mac (native)         │
│                   │                          │                              │
│  C++ Capture      │                          │  Python ML Inference         │
│  Agent (libpcap)  │                          │  → TimescaleDB               │
│                   │                          │  → FastAPI                   │
└──────────────────┘                          │  → Dashboard (HTML/JS)       │
                                               └─────────────────────────────┘
```

See `docs/FLOW_SCHEMA.md` for the exact JSON contract between components — **read this before
writing any parsing, training, or DB code.**

## Repo Structure

| Path | What Goes Here | Owner |
|---|---|---|
| `agent/` | C++ capture agent — packet parsing, flow aggregation, socket sender | Capture & Integration Lead |
| `ml/` | Dataset prep, model training, inference wrapper | ML / Data Lead |
| `db/` | TimescaleDB schema + DB writer | DB & Dashboard Lead |
| `api/` | FastAPI server (`/flows`, `/threats`, `/stats`) | DB & Dashboard Lead |
| `dashboard/` | HTML/JS/Chart.js frontend | DB & Dashboard Lead |
| `data/` | Training datasets (gitignored — don't commit large files) | ML / Data Lead |
| `docs/` | Shared specs (flow schema, etc.) | Everyone |

## Setup

### Mac (host — runs ML, DB, API, dashboard)
```bash
brew install postgresql@16
# Install TimescaleDB: https://docs.timescale.com/self-hosted/latest/install/
pip3 install -r ml/requirements.txt
```

### VM (UTM — runs capture agent only)
```bash
sudo apt install libpcap-dev cmake g++ git nlohmann-json3-dev
cd agent && mkdir build && cd build && cmake .. && make
```

## 8-Week Build Plan

| Week | Milestone |
|---|---|
| 1 | Environment setup + Hello World C++ packet counter |
| 2 | Packet parser + flow aggregation |
| 3 | Socket comms layer (agent → Mac) |
| 4 | TimescaleDB schema + writer |
| 5 | ML training on CICIDS2017 |
| 6 | Full pipeline integration |
| 7 | FastAPI + live dashboard |
| 8 | Stress testing + demo polish |

## Team

| Person | Role | Share |
|---|---|---|
| Abhimanyu Chettiar | Capture Agent & Integration Lead | 60% |
| Zaara Khan | ML / Data Lead | 20% |
| Bhupender | DB & Dashboard Lead | 20% |

## Branching

- `main` — always demo-able
- `feature/capture-agent`
- `feature/ml-pipeline`
- `feature/db-dashboard`

Open a PR into `main` when a weekly deliverable is done. See `CONTRIBUTING.md`.
