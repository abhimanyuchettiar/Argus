#include "parser.h"
#include <cstring>
#include <cmath>
#include <array>

namespace {

constexpr uint16_t ETHERTYPE_IP  = 0x0800;
constexpr size_t    ETH_HDR_LEN  = 14;

constexpr uint8_t PROTO_TCP  = 6;
constexpr uint8_t PROTO_UDP  = 17;
constexpr uint8_t PROTO_ICMP = 1;

uint16_t read_u16(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

uint32_t read_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
            static_cast<uint32_t>(p[3]);
}

} // namespace

double payload_entropy(const uint8_t* data, uint32_t len) {
    if (data == nullptr || len == 0) return 0.0;

    std::array<uint32_t, 256> freq{};
    for (uint32_t i = 0; i < len; ++i) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    for (uint32_t count : freq) {
        if (count == 0) continue;
        double p = static_cast<double>(count) / static_cast<double>(len);
        entropy -= p * std::log2(p);
    }
    return entropy; // 0 (uniform byte) .. 8 (max randomness)
}

std::optional<ParsedPacket> parse_packet(const uint8_t* data, uint32_t caplen) {
    if (data == nullptr || caplen < ETH_HDR_LEN) return std::nullopt;

    // --- Ethernet header ---
    uint16_t ethertype = read_u16(data + 12);
    if (ethertype != ETHERTYPE_IP) {
        return std::nullopt; // skip ARP, IPv6, VLAN-tagged, etc. for now
    }

    const uint8_t* ip_hdr = data + ETH_HDR_LEN;
    if (caplen < ETH_HDR_LEN + 20) return std::nullopt; // min IPv4 header

    // --- IPv4 header ---
    uint8_t version_ihl = ip_hdr[0];
    uint8_t version = version_ihl >> 4;
    if (version != 4) return std::nullopt;

    uint8_t ihl_words = version_ihl & 0x0F;
    size_t  ip_hdr_len = static_cast<size_t>(ihl_words) * 4;
    if (ip_hdr_len < 20 || caplen < ETH_HDR_LEN + ip_hdr_len) return std::nullopt;

    uint16_t total_len_field = read_u16(ip_hdr + 2);
    uint8_t  ip_protocol     = ip_hdr[9];
    uint32_t src_ip          = read_u32(ip_hdr + 12);
    uint32_t dst_ip          = read_u32(ip_hdr + 16);

    ParsedPacket pkt{};
    pkt.src_ip = src_ip;
    pkt.dst_ip = dst_ip;
    pkt.total_len = total_len_field != 0 ? total_len_field
                                          : static_cast<uint32_t>(caplen);

    const uint8_t* l4_hdr = ip_hdr + ip_hdr_len;
    size_t l4_available = caplen - ETH_HDR_LEN - ip_hdr_len;

    if (ip_protocol == PROTO_TCP) {
        if (l4_available < 20) return std::nullopt; // min TCP header
        pkt.protocol  = 0;
        pkt.src_port  = read_u16(l4_hdr);
        pkt.dst_port  = read_u16(l4_hdr + 2);

        uint8_t data_offset_flags = l4_hdr[12];
        size_t tcp_hdr_len = ((data_offset_flags >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < 20 || l4_available < tcp_hdr_len) return std::nullopt;

        uint8_t flags = l4_hdr[13];
        pkt.fin = flags & 0x01;
        pkt.syn = flags & 0x02;
        pkt.rst = flags & 0x04;
        pkt.psh = flags & 0x08;
        pkt.ack = flags & 0x10;

        pkt.payload = l4_hdr + tcp_hdr_len;
        pkt.payload_len = static_cast<uint32_t>(l4_available - tcp_hdr_len);
    } else if (ip_protocol == PROTO_UDP) {
        if (l4_available < 8) return std::nullopt; // UDP header
        pkt.protocol = 1;
        pkt.src_port = read_u16(l4_hdr);
        pkt.dst_port = read_u16(l4_hdr + 2);

        pkt.payload = l4_hdr + 8;
        pkt.payload_len = static_cast<uint32_t>(l4_available >= 8 ? l4_available - 8 : 0);
    } else if (ip_protocol == PROTO_ICMP) {
        pkt.protocol = 2;
        pkt.src_port = 0;
        pkt.dst_port = 0;
        pkt.payload = l4_available > 0 ? l4_hdr : nullptr;
        pkt.payload_len = static_cast<uint32_t>(l4_available);
    } else {
        return std::nullopt; // not a protocol we track (e.g. GRE, ESP)
    }

    return pkt;
}
