#include "sender.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ctime>
#include <iomanip>
#include <sstream>

namespace {
const char* protocol_name(uint8_t protocol) {
    return protocol == 0 ? "TCP" : protocol == 1 ? "UDP" : "ICMP";
}
std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') out << '\\' << static_cast<char>(c);
        else if (c < 0x20) out << ' ';
        else out << static_cast<char>(c);
    }
    return out.str();
}
std::string iso_timestamp(double epoch) {
    const auto seconds = static_cast<std::time_t>(epoch);
    const auto millis = static_cast<int>((epoch - static_cast<double>(seconds)) * 1000.0);
    std::tm utc{};
    gmtime_r(&seconds, &utc);
    std::ostringstream out;
    out << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(3) << std::setfill('0') << millis << 'Z';
    return out.str();
}
}

Sender::Sender(const std::string& host, int port) : host_(host), port_(port) {}

bool Sender::connect() {
    if (socket_fd_ >= 0) return true;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* addresses = nullptr;
    const std::string service = std::to_string(port_);
    if (getaddrinfo(host_.c_str(), service.c_str(), &hints, &addresses) != 0) return false;
    for (addrinfo* address = addresses; address; address = address->ai_next) {
        const int fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
            socket_fd_ = fd;
            break;
        }
        ::close(fd);
    }
    freeaddrinfo(addresses);
    return socket_fd_ >= 0;
}

bool Sender::send_flow(const FlowKey& key, const FlowFeatures& f, double timestamp) {
    if (!connect()) return false;
    std::ostringstream out;
    out << std::setprecision(10)
        << "{\"flow_id\":\"" << json_escape(key.src_ip) << ':' << key.src_port << '-'
        << json_escape(key.dst_ip) << ':' << key.dst_port << '-' << protocol_name(key.protocol)
        << "\",\"timestamp\":\"" << iso_timestamp(timestamp)
        << "\",\"src_ip\":\"" << json_escape(key.src_ip)
        << "\",\"dst_ip\":\"" << json_escape(key.dst_ip)
        << "\",\"src_port\":" << key.src_port << ",\"dst_port\":" << key.dst_port
        << ",\"protocol\":" << static_cast<int>(key.protocol)
        << ",\"features\":{\"packets_per_second\":" << f.packets_per_second
        << ",\"bytes_per_second\":" << f.bytes_per_second
        << ",\"avg_packet_size\":" << f.avg_packet_size
        << ",\"syn_ratio\":" << f.syn_ratio << ",\"fin_ratio\":" << f.fin_ratio
        << ",\"unique_dst_ports\":" << f.unique_dst_ports
        << ",\"flow_duration_ms\":" << f.flow_duration_ms
        << ",\"protocol_encoded\":" << f.protocol_encoded
        << ",\"dst_port_val\":" << f.dst_port_val
        << ",\"payload_entropy\":" << f.payload_entropy
        << ",\"inter_arrival_mean\":" << f.inter_arrival_mean
        << ",\"inter_arrival_std\":" << f.inter_arrival_std
        << ",\"psh_ratio\":" << f.psh_ratio << ",\"ack_ratio\":" << f.ack_ratio
        << ",\"rst_ratio\":" << f.rst_ratio << "}}\n";
    const std::string payload = out.str();
    size_t sent = 0;
    while (sent < payload.size()) {
        const ssize_t count = ::send(socket_fd_, payload.data() + sent, payload.size() - sent, 0);
        if (count <= 0) {
            close();
            return false;
        }
        sent += static_cast<size_t>(count);
    }
    return true;
}

void Sender::close() {
    if (socket_fd_ >= 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
}
