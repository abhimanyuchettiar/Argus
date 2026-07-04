#include "parser.h"

// TODO(week 2): Walk Ethernet header (14 bytes) -> check EtherType for IPv4 (0x0800)
// -> walk IP header (variable length via IHL field) -> get protocol byte
// -> walk TCP (flags at byte offset 13) or UDP header.
//
// Reference: Beej's Guide to Network Programming (beej.us/guide/bgnet)
// Reference: blueprint.pdf section 3.1 "Capture Agent — C++"

PacketInfo parse_packet(const unsigned char* packet_data, uint32_t length, double timestamp) {
    PacketInfo info;
    info.timestamp = timestamp;

    (void)packet_data;
    (void)length;

    // Placeholder — replace with real header parsing.
    return info;
}

bool FlowKey::operator==(const FlowKey& other) const {
    return src_ip == other.src_ip &&
           dst_ip == other.dst_ip &&
           src_port == other.src_port &&
           dst_port == other.dst_port &&
           protocol == other.protocol;
}

std::size_t FlowKeyHash::operator()(const FlowKey& key) const {
    std::size_t h1 = std::hash<std::string>{}(key.src_ip);
    std::size_t h2 = std::hash<std::string>{}(key.dst_ip);
    std::size_t h3 = std::hash<uint16_t>{}(key.src_port);
    std::size_t h4 = std::hash<uint16_t>{}(key.dst_port);
    std::size_t h5 = std::hash<uint8_t>{}(key.protocol);
    return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
}
