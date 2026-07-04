#include "flow.h"

void FlowStats::update(const PacketInfo& pkt) {
    packet_count++;
    byte_count += pkt.packet_size;
    if (pkt.syn) syn_count++;
    if (pkt.fin) fin_count++;
    if (pkt.psh) psh_count++;
    if (pkt.ack) ack_count++;
    if (pkt.rst) rst_count++;

    if (first_seen == 0.0) {
        first_seen = pkt.timestamp;
    }
    last_seen = pkt.timestamp;
}

FlowFeatures compute_features(const FlowStats& stats, uint16_t dst_port, uint8_t protocol) {
    FlowFeatures f{};

    double duration_s = stats.last_seen - stats.first_seen;
    if (duration_s <= 0.0) duration_s = 0.001; // avoid divide-by-zero on single-packet flows

    f.packets_per_second = static_cast<double>(stats.packet_count) / duration_s;
    f.bytes_per_second = static_cast<double>(stats.byte_count) / duration_s;
    f.avg_packet_size = stats.packet_count > 0
        ? static_cast<double>(stats.byte_count) / stats.packet_count
        : 0.0;
    f.syn_ratio = stats.packet_count > 0 ? static_cast<double>(stats.syn_count) / stats.packet_count : 0.0;
    f.fin_ratio = stats.packet_count > 0 ? static_cast<double>(stats.fin_count) / stats.packet_count : 0.0;
    f.unique_dst_ports = static_cast<int>(stats.unique_dst_ports);
    f.flow_duration_ms = static_cast<int>(duration_s * 1000);
    f.protocol_encoded = protocol;
    f.dst_port_val = dst_port;

    // TODO(week 2): payload_entropy, inter_arrival_mean/std need per-packet timing/payload
    // history, not just running totals — you'll likely need to store a small vector of
    // inter-arrival times and payload byte samples in FlowStats to compute these properly.
    f.payload_entropy = 0.0;
    f.inter_arrival_mean = 0.0;
    f.inter_arrival_std = 0.0;

    f.psh_ratio = stats.packet_count > 0 ? static_cast<double>(stats.psh_count) / stats.packet_count : 0.0;
    f.ack_ratio = stats.packet_count > 0 ? static_cast<double>(stats.ack_count) / stats.packet_count : 0.0;
    f.rst_ratio = stats.packet_count > 0 ? static_cast<double>(stats.rst_count) / stats.packet_count : 0.0;

    return f;
}
