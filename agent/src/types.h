#pragma once
#include <cstdint>
#include <chrono>
#include <unordered_set>

// Uniquely identifies a flow
struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol; // 0=TCP, 1=UDP, 2=ICMP

    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const {
        std::size_t h = std::hash<uint32_t>()(k.src_ip);
        h ^= std::hash<uint32_t>()(k.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>()(k.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>()(k.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>()(k.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

// Raw accumulator updated per-packet. One instance per active flow.
struct FlowStats {
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
    uint64_t syn_count = 0;
    uint64_t fin_count = 0;
    uint64_t ack_count = 0;
    uint64_t psh_count = 0;
    uint64_t rst_count = 0;

    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    bool has_last_packet_time = false;
    std::chrono::steady_clock::time_point last_packet_time;

    // Welford-style running stats for inter-arrival time (ms)
    double ia_mean = 0.0;
    double ia_m2 = 0.0; // sum of squared diffs from mean
    uint64_t ia_samples = 0;

    // Running mean of per-packet payload entropy (0-8 bits/byte)
    double entropy_sum = 0.0;
    uint64_t entropy_samples = 0;

    std::unordered_set<uint16_t> unique_dst_ports;
};

// The 15 normalized features fed to the ML model. Field order/names
// intentionally mirror docs/FLOW_SCHEMA.md - verify against that file
// before merging into the shared branch.
struct FlowFeatures {
    double packets_per_second;
    double bytes_per_second;
    double avg_packet_size;
    double syn_ratio;
    double fin_ratio;
    int    unique_dst_ports;
    double flow_duration_ms;
    int    protocol; // 0=TCP, 1=UDP, 2=ICMP
    int    dst_port;
    double payload_entropy;
    double inter_arrival_mean;
    double inter_arrival_std;
    double psh_ratio;
    double ack_ratio;
    double rst_ratio;
};
