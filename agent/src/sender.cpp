#include "sender.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

Sender::Sender(std::string host, uint16_t port)
    : host_(std::move(host)), port_(port) {}

Sender::~Sender() {
    close_socket();
}

void Sender::close_socket() {
    if (sockfd_ >= 0) {
        close(sockfd_);
        sockfd_ = -1;
    }
}

std::string Sender::ip_to_string(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << '.' << ((ip >> 16) & 0xFF) << '.'
        << ((ip >> 8) & 0xFF) << '.' << (ip & 0xFF);
    return oss.str();
}

namespace {

const char* protocol_name(int protocol) {
    switch (protocol) {
        case 0: return "TCP";
        case 1: return "UDP";
        case 2: return "ICMP";
        default: return "UNKNOWN";
    }
}

// ISO 8601 UTC with millisecond precision, e.g. "2026-07-04T14:32:01.123Z"
// Matches docs/FLOW_SCHEMA.md section 1 exactly.
std::string iso8601_now() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t t = system_clock::to_time_t(now);

    std::tm utc_tm{};
    gmtime_r(&t, &utc_tm);

    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &utc_tm);

    std::ostringstream oss;
    oss << buf << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return oss.str();
}

} // namespace

bool Sender::connect_if_needed() {
    if (sockfd_ >= 0) return true;

    auto now = std::chrono::steady_clock::now();
    if (last_attempt_.time_since_epoch().count() != 0 &&
        now - last_attempt_ < backoff_) {
        return false; // still in backoff window
    }
    last_attempt_ = now;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "[sender] socket() failed: " << strerror(errno) << "\n";
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "[sender] invalid host: " << host_ << "\n";
        close(fd);
        return false;
    }

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[sender] connect() to " << host_ << ":" << port_
                   << " failed: " << strerror(errno)
                   << " (retrying in " << backoff_.count() << "ms)\n";
        close(fd);
        backoff_ = std::min(backoff_ * 2, kMaxBackoff);
        return false;
    }

    sockfd_ = fd;
    backoff_ = std::chrono::milliseconds{500}; // reset backoff on success
    std::cerr << "[sender] connected to " << host_ << ":" << port_ << "\n";
    return true;
}

bool Sender::send_flow(const FlowKey& key, const FlowFeatures& f) {
    if (!connect_if_needed()) return false;

    std::string src_ip_str = ip_to_string(key.src_ip);
    std::string dst_ip_str = ip_to_string(key.dst_ip);

    std::ostringstream flow_id;
    flow_id << src_ip_str << ':' << key.src_port << '-'
            << dst_ip_str << ':' << f.dst_port << '-'
            << protocol_name(f.protocol);

    json j;
    j["flow_id"]   = flow_id.str();
    j["timestamp"] = iso8601_now();
    j["src_ip"]    = src_ip_str;
    j["dst_ip"]    = dst_ip_str;
    j["src_port"]  = key.src_port;
    j["dst_port"]  = f.dst_port;
    j["protocol"]  = f.protocol; // 0=TCP, 1=UDP, 2=ICMP

    // Nested "features" object - order/names must match
    // docs/FLOW_SCHEMA.md section 3 exactly (ML training columns depend on it).
    json features;
    features["packets_per_second"] = f.packets_per_second;
    features["bytes_per_second"]   = f.bytes_per_second;
    features["avg_packet_size"]    = f.avg_packet_size;
    features["syn_ratio"]          = f.syn_ratio;
    features["fin_ratio"]          = f.fin_ratio;
    features["unique_dst_ports"]   = f.unique_dst_ports;
    features["flow_duration_ms"]   = static_cast<int64_t>(f.flow_duration_ms);
    features["protocol_encoded"]   = f.protocol;
    features["dst_port_val"]       = f.dst_port;
    features["payload_entropy"]    = f.payload_entropy;
    // FlowStats accumulates inter-arrival time in milliseconds; the
    // schema wants seconds - convert here rather than in FlowTable so
    // flow.cpp's internal units stay millisecond-precision throughout.
    features["inter_arrival_mean"] = f.inter_arrival_mean / 1000.0;
    features["inter_arrival_std"]  = f.inter_arrival_std / 1000.0;
    features["psh_ratio"]          = f.psh_ratio;
    features["ack_ratio"]          = f.ack_ratio;
    features["rst_ratio"]          = f.rst_ratio;

    j["features"] = features;

    // Newline-delimited JSON - the Python listener reads line by line.
    std::string payload = j.dump() + "\n";

    ssize_t sent = send(sockfd_, payload.data(), payload.size(), MSG_NOSIGNAL);
    if (sent < 0 || static_cast<size_t>(sent) != payload.size()) {
        std::cerr << "[sender] send() failed, dropping connection: "
                   << strerror(errno) << "\n";
        close_socket();
        return false;
    }
    return true;
}
