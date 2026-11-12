#pragma once
#include <string>
#include <chrono>
#include "types.h"

// Sends flow feature JSON over a TCP socket to the Mac-side Python
// listener (ml/listener.py). If the Mac drops, the agent keeps
// capturing/aggregating in the background - send() just returns false
// and connect_if_needed() retries with backoff on the next call.
class Sender {
public:
    Sender(std::string host, uint16_t port);
    ~Sender();

    // Attempts to (re)connect if not currently connected. Cheap no-op
    // if already connected or if a backoff window hasn't elapsed yet.
    bool connect_if_needed();

    // Serializes key+features as one JSON line and sends it.
    // Returns false (and drops the connection) on any socket error.
    bool send_flow(const FlowKey& key, const FlowFeatures& features);

    bool is_connected() const { return sockfd_ >= 0; }

private:
    std::string host_;
    uint16_t port_;
    int sockfd_ = -1;

    std::chrono::steady_clock::time_point last_attempt_{};
    std::chrono::milliseconds backoff_{500};
    static constexpr std::chrono::milliseconds kMaxBackoff{10000};

    void close_socket();
    static std::string ip_to_string(uint32_t ip_be_order);
};
