#include "flow.h"
#include <cmath>
#include <algorithm>

using clock_t = std::chrono::steady_clock;

void FlowTable::process_packet(const ParsedPacket& pkt) {
    FlowKey key{pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol};
    auto now = clock_t::now();

    std::lock_guard<std::mutex> lock(mutex_);
    auto& stats = flows_[key]; // default-constructs on first packet

    if (stats.packet_count == 0) {
        stats.first_seen = now;
    }
    stats.last_seen = now;

    if (stats.has_last_packet_time) {
        double ia_ms = std::chrono::duration<double, std::milli>(
                           now - stats.last_packet_time).count();
        // Welford's online mean/variance update
        stats.ia_samples++;
        double delta = ia_ms - stats.ia_mean;
        stats.ia_mean += delta / static_cast<double>(stats.ia_samples);
        double delta2 = ia_ms - stats.ia_mean;
        stats.ia_m2 += delta * delta2;
    }
    stats.last_packet_time = now;
    stats.has_last_packet_time = true;

    stats.packet_count++;
    stats.byte_count += pkt.total_len;
    if (pkt.syn) stats.syn_count++;
    if (pkt.fin) stats.fin_count++;
    if (pkt.ack) stats.ack_count++;
    if (pkt.psh) stats.psh_count++;
    if (pkt.rst) stats.rst_count++;

    stats.unique_dst_ports.insert(pkt.dst_port);

    if (pkt.payload != nullptr && pkt.payload_len > 0) {
        stats.entropy_sum += payload_entropy(pkt.payload, pkt.payload_len);
        stats.entropy_samples++;
    }
}

FlowFeatures FlowTable::compute_features(const FlowKey& key, const FlowStats& stats) {
    FlowFeatures f{};

    double duration_s = std::chrono::duration<double>(
                             stats.last_seen - stats.first_seen).count();
    // Guard against div-by-zero for single-packet flows.
    double safe_duration_s = std::max(duration_s, 0.001);

    f.packets_per_second = static_cast<double>(stats.packet_count) / safe_duration_s;
    f.bytes_per_second    = static_cast<double>(stats.byte_count) / safe_duration_s;
    f.avg_packet_size     = stats.packet_count > 0
                                 ? static_cast<double>(stats.byte_count) / stats.packet_count
                                 : 0.0;

    f.syn_ratio = stats.packet_count > 0
                      ? static_cast<double>(stats.syn_count) / stats.packet_count : 0.0;
    f.fin_ratio = stats.packet_count > 0
                      ? static_cast<double>(stats.fin_count) / stats.packet_count : 0.0;
    f.psh_ratio = stats.packet_count > 0
                      ? static_cast<double>(stats.psh_count) / stats.packet_count : 0.0;
    f.ack_ratio = stats.packet_count > 0
                      ? static_cast<double>(stats.ack_count) / stats.packet_count : 0.0;
    f.rst_ratio = stats.packet_count > 0
                      ? static_cast<double>(stats.rst_count) / stats.packet_count : 0.0;

    f.unique_dst_ports = static_cast<int>(stats.unique_dst_ports.size());
    f.flow_duration_ms = duration_s * 1000.0;
    f.protocol = key.protocol;
    f.dst_port = key.dst_port;

    f.payload_entropy = stats.entropy_samples > 0
                             ? stats.entropy_sum / stats.entropy_samples : 0.0;

    f.inter_arrival_mean = stats.ia_samples > 0 ? stats.ia_mean : 0.0;
    f.inter_arrival_std  = stats.ia_samples > 1
                                ? std::sqrt(stats.ia_m2 / static_cast<double>(stats.ia_samples))
                                : 0.0;

    return f;
}

std::vector<std::pair<FlowKey, FlowFeatures>> FlowTable::flush() {
    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> swapped;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::swap(swapped, flows_); // O(1) - just pointer/bucket swap
    }
    // Everything below runs lock-free against a private copy.

    std::vector<std::pair<FlowKey, FlowFeatures>> results;
    results.reserve(swapped.size());
    for (const auto& [key, stats] : swapped) {
        results.emplace_back(key, compute_features(key, stats));
    }
    return results;
}
