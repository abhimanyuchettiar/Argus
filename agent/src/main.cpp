// Argus IPv4 packet capture, per-flow aggregation, and TCP flow sender.
#include <pcap.h>
#include "flow.h"
#include "parser.h"
#include "sender.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <unordered_map>

static std::atomic<bool> running{true};
static void handle_signal(int) { running = false; }

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s <interface> [listener-host] [listener-port]\n", argv[0]);
        return 2;
    }
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    const char* interface = argv[1];
    const char* listener_host = argc > 2 ? argv[2] : "127.0.0.1";
    const int listener_port = argc > 3 ? std::atoi(argv[3]) : 9999;

    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t* capture = pcap_open_live(interface, BUFSIZ, 1, 500, errbuf);
    if (!capture) {
        std::fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }
    Sender sender(listener_host, listener_port);
    FlowTable flows;
    auto last_flush = std::chrono::steady_clock::now();
    std::fprintf(stdout, "[agent] capturing on %s, sending to %s:%d\n", interface, listener_host, listener_port);

    while (running) {
        pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;
        const int rc = pcap_next_ex(capture, &header, &packet);
        if (rc == 1 && header && packet) {
            const double timestamp = static_cast<double>(header->ts.tv_sec) + header->ts.tv_usec / 1e6;
            const PacketInfo info = parse_packet(packet, header->caplen, timestamp);
            if (info.valid) {
                FlowKey key{info.src_ip, info.dst_ip, info.src_port, info.dst_port, info.protocol};
                flows[key].update(info);
            }
        } else if (rc == -1) {
            std::fprintf(stderr, "pcap capture failed: %s\n", pcap_geterr(capture));
            break;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now - last_flush >= std::chrono::seconds(1)) {
            for (const auto& entry : flows) {
                const auto& key = entry.first;
                const auto& stats = entry.second;
                const auto features = compute_features(stats, key.dst_port, key.protocol);
                if (!sender.send_flow(key, features, stats.last_seen)) {
                    std::fprintf(stderr, "[agent] unable to send flow to listener\n");
                }
            }
            flows.clear();
            last_flush = now;
        }
    }
    sender.close();
    pcap_close(capture);
    return 0;
}
