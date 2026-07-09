#pragma once
#include <cstdint>
#include <cstddef>
#include <optional>

// Result of parsing one raw packet off the wire.
struct ParsedPacket {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;  // 0 if not TCP/UDP
    uint16_t dst_port;  // 0 if not TCP/UDP
    uint8_t  protocol;  // 0=TCP, 1=UDP, 2=ICMP
    uint32_t total_len; // wire length of the packet
    uint32_t payload_len;
    const uint8_t* payload; // pointer into original buffer, not owned

    bool syn = false;
    bool fin = false;
    bool ack = false;
    bool psh = false;
    bool rst = false;
};

// Parses an Ethernet frame captured by libpcap and walks the
// Ethernet -> IP -> TCP/UDP/ICMP chain manually via byte offsets.
// Returns std::nullopt for anything we don't care about (ARP, IPv6, etc).
std::optional<ParsedPacket> parse_packet(const uint8_t* data, uint32_t caplen);

// Shannon entropy (bits/byte, 0-8) of a payload buffer. Used as a
// per-packet signal that gets rolled into the flow's running average.
double payload_entropy(const uint8_t* data, uint32_t len);
