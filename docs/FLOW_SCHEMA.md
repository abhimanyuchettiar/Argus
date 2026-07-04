# Argus — Flow Data Contract (v1.0)

This is the **single source of truth** for the JSON payload that flows between components:

`C++ Agent → Python ML Listener → DB Writer`

If you need to change a field, change it here first, then post in the group chat — don't
silently rename something in your own branch. Every teammate's code depends on these exact
key names and types matching.

---

## 1. The Flow JSON Object

Sent once per completed flow window (every ~1 second) from the C++ agent over the TCP socket.

```json
{
  "flow_id": "10.0.0.5:52344-10.0.0.12:443-TCP",
  "timestamp": "2026-07-04T14:32:01.123Z",
  "src_ip": "10.0.0.5",
  "dst_ip": "10.0.0.12",
  "src_port": 52344,
  "dst_port": 443,
  "protocol": 0,
  "features": {
    "packets_per_second": 12.4,
    "bytes_per_second": 8342.7,
    "avg_packet_size": 673.1,
    "syn_ratio": 0.02,
    "fin_ratio": 0.01,
    "unique_dst_ports": 1,
    "flow_duration_ms": 4521,
    "protocol_encoded": 0,
    "dst_port_val": 443,
    "payload_entropy": 3.8,
    "inter_arrival_mean": 0.081,
    "inter_arrival_std": 0.012,
    "psh_ratio": 0.15,
    "ack_ratio": 0.62,
    "rst_ratio": 0.0
  }
}
```

## 2. Field Reference

| Field | Type | Owner (produces it) | Notes |
|---|---|---|---|
| `flow_id` | string | C++ agent | `src_ip:src_port-dst_ip:dst_port-PROTO`, useful for debugging/logs |
| `timestamp` | string (ISO 8601, UTC) | C++ agent | When the flow window closed |
| `src_ip` / `dst_ip` | string | C++ agent | IPv4 dotted notation |
| `src_port` / `dst_port` | integer | C++ agent | 0–65535 |
| `protocol` | integer | C++ agent | `0 = TCP, 1 = UDP, 2 = ICMP` |
| `features` | object | C++ agent | The 15 values fed straight into the ML model — **order and names must match training data columns exactly** |

## 3. The 15 Features (must match blueprint spec exactly)

| # | Key | Type | Range/notes |
|---|---|---|---|
| 1 | `packets_per_second` | float | ≥ 0 |
| 2 | `bytes_per_second` | float | ≥ 0 |
| 3 | `avg_packet_size` | float | bytes |
| 4 | `syn_ratio` | float | 0.0–1.0 |
| 5 | `fin_ratio` | float | 0.0–1.0 |
| 6 | `unique_dst_ports` | integer | ≥ 1 |
| 7 | `flow_duration_ms` | integer | ≥ 0 |
| 8 | `protocol_encoded` | integer | 0=TCP, 1=UDP, 2=ICMP |
| 9 | `dst_port_val` | integer | 0–65535 |
| 10 | `payload_entropy` | float | 0.0–8.0 (Shannon entropy) |
| 11 | `inter_arrival_mean` | float | seconds |
| 12 | `inter_arrival_std` | float | seconds |
| 13 | `psh_ratio` | float | 0.0–1.0 |
| 14 | `ack_ratio` | float | 0.0–1.0 |
| 15 | `rst_ratio` | float | 0.0–1.0 |

**Whoever trains the model (feature engineering step) must produce their pandas DataFrame
columns in this exact order with these exact names** — if column order drifts from what the
C++ agent sends, the model will silently make garbage predictions without erroring.

## 4. The Verdict JSON Object

Sent from the ML inference step back to the DB writer / API layer:

```json
{
  "flow_id": "10.0.0.5:52344-10.0.0.12:443-TCP",
  "label": "port_scan",
  "confidence": 0.94,
  "severity": "HIGH"
}
```

| Field | Type | Notes |
|---|---|---|
| `label` | string | One of: `normal`, `port_scan`, `ddos`, `brute_force`, `dns_amplification`, `arp_spoof`, `exfiltration` |
| `confidence` | float | 0.0–1.0 |
| `severity` | string | `LOW`, `MEDIUM`, `HIGH` — derived from confidence + label, not from the model directly |

## 5. Change Log

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-07-04 | Initial contract |

> Bump the version number and add a row here any time a field is added/renamed/removed.
> Don't just edit silently — the other two people's code is depending on this file staying stable.
