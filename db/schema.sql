-- Argus database schema
-- Requires: PostgreSQL 16 + TimescaleDB extension + pgvector extension
--
-- Setup:
--   CREATE EXTENSION IF NOT EXISTS timescaledb;
--   CREATE EXTENSION IF NOT EXISTS vector;

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS vector;

-- Every flow event, time-indexed. See docs/FLOW_SCHEMA.md for field meanings.
CREATE TABLE IF NOT EXISTS network_flows (
    time             TIMESTAMPTZ       NOT NULL,
    flow_id          TEXT              NOT NULL,
    src_ip           INET              NOT NULL,
    dst_ip           INET              NOT NULL,
    src_port         INTEGER           NOT NULL,
    dst_port         INTEGER           NOT NULL,
    protocol         SMALLINT          NOT NULL,
    packets_per_second   DOUBLE PRECISION,
    bytes_per_second      DOUBLE PRECISION,
    avg_packet_size       DOUBLE PRECISION,
    syn_ratio             DOUBLE PRECISION,
    fin_ratio             DOUBLE PRECISION,
    unique_dst_ports      INTEGER,
    flow_duration_ms      INTEGER,
    payload_entropy       DOUBLE PRECISION,
    inter_arrival_mean    DOUBLE PRECISION,
    inter_arrival_std     DOUBLE PRECISION,
    psh_ratio             DOUBLE PRECISION,
    ack_ratio             DOUBLE PRECISION,
    rst_ratio             DOUBLE PRECISION
);

SELECT create_hypertable('network_flows', 'time', if_not_exists => TRUE);

-- Classified threats only — written when ML confidence crosses the alert threshold.
CREATE TABLE IF NOT EXISTS threat_events (
    time         TIMESTAMPTZ NOT NULL,
    flow_id      TEXT        NOT NULL,
    src_ip       INET        NOT NULL,
    label        TEXT        NOT NULL,
    confidence   DOUBLE PRECISION NOT NULL,
    severity     TEXT        NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH'))
);

SELECT create_hypertable('threat_events', 'time', if_not_exists => TRUE);

-- Vector representation of flows for similarity search ("find flows like this attack").
-- TODO(week 4/6): pick an embedding dimension that matches whatever you use to vectorize
-- flow features (e.g. the 15 raw features, or a learned embedding). 15 is a placeholder.
CREATE TABLE IF NOT EXISTS flow_embeddings (
    flow_id    TEXT PRIMARY KEY,
    embedding  VECTOR(15) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Metadata about each capture run — useful for the demo ("show last 60 seconds").
CREATE TABLE IF NOT EXISTS capture_sessions (
    id          SERIAL PRIMARY KEY,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at    TIMESTAMPTZ,
    notes       TEXT
);

-- Handy starter queries (blueprint section 4, Week 4 deliverable):
--   Flows in last 5 min:
--     SELECT * FROM network_flows WHERE time > now() - INTERVAL '5 minutes';
--   Top src IPs:
--     SELECT src_ip, COUNT(*) FROM network_flows GROUP BY src_ip ORDER BY 2 DESC LIMIT 10;
--   Protocol breakdown:
--     SELECT protocol, COUNT(*) FROM network_flows GROUP BY protocol;
