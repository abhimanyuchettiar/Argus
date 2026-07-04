#pragma once
#include <cstdint>
#include <unordered_map>
#include "parser.h"

// Running stats for a single flow, updated as packets arrive.
struct FlowStats {
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
    uint64_t syn_count = 0;
    uint64_t fin_count = 0;
    uint64_t psh_count = 0;
    uint64_t ack_count = 0;
    uint64_t rst_count = 0;
    double first_seen = 0.0;
    double last_seen = 0.0;
    uint32_t unique_dst_ports = 0; // TODO: track via a small set per src_ip if needed

    void update(const PacketInfo& pkt);
};

// The 15 features fed to the ML model. Field names MUST match docs/FLOW_SCHEMA.md exactly.
struct FlowFeatures {
    double packets_per_second;
    double bytes_per_second;
    double avg_packet_size;
    double syn_ratio;
    double fin_ratio;
    int unique_dst_ports;
    int flow_duration_ms;
    int protocol_encoded;
    int dst_port_val;
    double payload_entropy;
    double inter_arrival_mean;
    double inter_arrival_std;
    double psh_ratio;
    double ack_ratio;
    double rst_ratio;
};

// TODO(week 2): Compute FlowFeatures from accumulated FlowStats.
FlowFeatures compute_features(const FlowStats& stats, uint16_t dst_port, uint8_t protocol);

using FlowTable = std::unordered_map<FlowKey, FlowStats, FlowKeyHash>;
