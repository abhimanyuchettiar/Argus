#pragma once
#include <cstdint>
#include <string>

// Uniquely identifies a flow. See docs/FLOW_SCHEMA.md for the JSON this maps to.
struct FlowKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol; // 0=TCP, 1=UDP, 2=ICMP

    bool operator==(const FlowKey& other) const;
};

// Hash support so FlowKey can be used in std::unordered_map (see flow.h)
struct FlowKeyHash {
    std::size_t operator()(const FlowKey& key) const;
};

// Raw per-packet info extracted by walking the header chain.
struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;
    uint32_t packet_size = 0;
    bool syn = false;
    bool fin = false;
    bool psh = false;
    bool ack = false;
    bool rst = false;
    double timestamp = 0.0; // seconds since epoch, from pcap header
};

// TODO(week 2): Implement in parser.cpp
// Walks Ethernet -> IP -> TCP/UDP headers by byte offset and fills PacketInfo.
// See blueprint section 3.1 for the exact header layout to expect.
PacketInfo parse_packet(const unsigned char* packet_data, uint32_t length, double timestamp);
