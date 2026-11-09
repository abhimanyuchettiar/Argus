#include "parser.h"

#include <arpa/inet.h>
#include <cstring>

namespace {
uint16_t read_be16(const unsigned char* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}
}

PacketInfo parse_packet(const unsigned char* data, uint32_t length, double timestamp) {
    PacketInfo info{};
    info.timestamp = timestamp;
    info.packet_size = length;
    if (!data || length < 14) return info;

    const uint16_t ether_type = read_be16(data + 12);
    if (ether_type != 0x0800 || length < 34) return info; // Ethernet + IPv4 only.

    const unsigned char* ip = data + 14;
    const uint8_t version_ihl = ip[0];
    if ((version_ihl >> 4) != 4) return info;
    const uint32_t ip_header_len = (version_ihl & 0x0f) * 4;
    if (ip_header_len < 20 || length < 14 + ip_header_len) return info;

    char src[INET_ADDRSTRLEN]{};
    char dst[INET_ADDRSTRLEN]{};
    if (!inet_ntop(AF_INET, ip + 12, src, sizeof(src)) || !inet_ntop(AF_INET, ip + 16, dst, sizeof(dst))) return info;
    info.src_ip = src;
    info.dst_ip = dst;

    const uint8_t ip_protocol = ip[9];
    const unsigned char* transport = ip + ip_header_len;
    const uint32_t transport_offset = 14 + ip_header_len;
    if (ip_protocol == 6) {
        if (length < transport_offset + 20) return PacketInfo{};
        info.protocol = 0;
        info.src_port = read_be16(transport);
        info.dst_port = read_be16(transport + 2);
        const uint8_t flags = transport[13];
        info.fin = (flags & 0x01) != 0;
        info.syn = (flags & 0x02) != 0;
        info.rst = (flags & 0x04) != 0;
        info.psh = (flags & 0x08) != 0;
        info.ack = (flags & 0x10) != 0;
    } else if (ip_protocol == 17) {
        if (length < transport_offset + 8) return PacketInfo{};
        info.protocol = 1;
        info.src_port = read_be16(transport);
        info.dst_port = read_be16(transport + 2);
    } else if (ip_protocol == 1) {
        info.protocol = 2;
    } else {
        return PacketInfo{};
    }
    info.valid = true;
    return info;
}

bool FlowKey::operator==(const FlowKey& other) const {
    return src_ip == other.src_ip && dst_ip == other.dst_ip && src_port == other.src_port &&
           dst_port == other.dst_port && protocol == other.protocol;
}

std::size_t FlowKeyHash::operator()(const FlowKey& key) const {
    std::size_t h = std::hash<std::string>{}(key.src_ip);
    h ^= std::hash<std::string>{}(key.dst_ip) << 1;
    h ^= std::hash<uint16_t>{}(key.src_port) << 2;
    h ^= std::hash<uint16_t>{}(key.dst_port) << 3;
    h ^= std::hash<uint8_t>{}(key.protocol) << 4;
    return h;
}
