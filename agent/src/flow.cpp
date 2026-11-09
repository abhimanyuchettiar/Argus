#include "flow.h"

void FlowStats::update(const PacketInfo& pkt) {
    ++packet_count;
    byte_count += pkt.packet_size;
    syn_count += pkt.syn;
    fin_count += pkt.fin;
    psh_count += pkt.psh;
    ack_count += pkt.ack;
    rst_count += pkt.rst;
    if (first_seen == 0.0) first_seen = pkt.timestamp;
    last_seen = pkt.timestamp;
}

FlowFeatures compute_features(const FlowStats& stats, uint16_t dst_port, uint8_t protocol) {
    FlowFeatures f{};
    const double duration = stats.last_seen - stats.first_seen;
    const double safe_duration = duration > 0.0 ? duration : 0.001;
    const double packets = static_cast<double>(stats.packet_count);
    f.packets_per_second = packets / safe_duration;
    f.bytes_per_second = static_cast<double>(stats.byte_count) / safe_duration;
    f.avg_packet_size = packets > 0 ? static_cast<double>(stats.byte_count) / packets : 0.0;
    f.syn_ratio = packets > 0 ? static_cast<double>(stats.syn_count) / packets : 0.0;
    f.fin_ratio = packets > 0 ? static_cast<double>(stats.fin_count) / packets : 0.0;
    f.unique_dst_ports = 1;
    f.flow_duration_ms = static_cast<int>(duration * 1000.0);
    f.protocol_encoded = protocol;
    f.dst_port_val = dst_port;
    f.payload_entropy = 0.0;
    f.inter_arrival_mean = 0.0;
    f.inter_arrival_std = 0.0;
    f.psh_ratio = packets > 0 ? static_cast<double>(stats.psh_count) / packets : 0.0;
    f.ack_ratio = packets > 0 ? static_cast<double>(stats.ack_count) / packets : 0.0;
    f.rst_ratio = packets > 0 ? static_cast<double>(stats.rst_count) / packets : 0.0;
    return f;
}
