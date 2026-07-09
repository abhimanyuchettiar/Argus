#pragma once
#include <unordered_map>
#include <mutex>
#include <vector>
#include <utility>
#include "types.h"
#include "parser.h"

// Thread-safe per-flow aggregator.
//
// Concurrency model: the capture thread calls process_packet() constantly.
// Once a second, the sender thread calls flush(), which SWAPS the live
// map with a fresh empty one under a short lock and does all the feature
// computation on the swapped-out copy with no lock held. This is the
// double-buffer pattern - it keeps the capture thread's lock hold time
// to a few instructions instead of blocking it on JSON/socket work.
class FlowTable {
public:
    void process_packet(const ParsedPacket& pkt);

    // Swaps out the current window's flows and returns computed features
    // for each one. Safe to call from a different thread than
    // process_packet().
    std::vector<std::pair<FlowKey, FlowFeatures>> flush();

private:
    std::mutex mutex_;
    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows_;

    static FlowFeatures compute_features(const FlowKey& key, const FlowStats& stats);
};
