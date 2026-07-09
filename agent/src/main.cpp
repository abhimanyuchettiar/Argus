#include <pcap.h>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <iostream>
#include <cstring>

#include "types.h"
#include "parser.h"
#include "flow.h"
#include "sender.h"

namespace {

std::atomic<bool> g_running{true};

void handle_signal(int) {
    g_running.store(false);
}

// Bundles what the pcap callback needs without using global state
// (aside from g_running).
struct CaptureContext {
    FlowTable* flow_table;
    std::atomic<uint64_t> packet_count{0};
};

void packet_handler(u_char* user, const struct pcap_pkthdr* header,
                     const u_char* bytes) {
    auto* ctx = reinterpret_cast<CaptureContext*>(user);
    ctx->packet_count.fetch_add(1, std::memory_order_relaxed);

    auto parsed = parse_packet(bytes, header->caplen);
    if (parsed.has_value()) {
        // Wire length in FlowStats should reflect the packet on the wire,
        // not just the parsed payload - use header->len (pre-truncation).
        parsed->total_len = header->len;
        ctx->flow_table->process_packet(*parsed);
    }
}

} // namespace

int main(int argc, char** argv) {
    std::string iface = argc > 1 ? argv[1] : "eth0";
    std::string mac_host = argc > 2 ? argv[2] : "127.0.0.1";
    uint16_t mac_port = argc > 3 ? static_cast<uint16_t>(std::stoi(argv[3])) : 9999;

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.c_str(), /*snaplen=*/65535,
                                     /*promisc=*/1, /*to_ms=*/1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "[agent] pcap_open_live failed on " << iface
                   << ": " << errbuf << "\n";
        return 1;
    }

    // Optional but recommended: only capture IPv4 to cut noise early.
    struct bpf_program filter{};
    if (pcap_compile(handle, &filter, "ip", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &filter);
        pcap_freecode(&filter);
    }

    FlowTable flow_table;
    CaptureContext ctx{&flow_table};
    Sender sender(mac_host, mac_port);

    std::cerr << "[agent] capturing on " << iface << ", streaming to "
               << mac_host << ":" << mac_port << "\n";

    // Capture thread: pcap_dispatch in short bursts so we can check
    // g_running and exit promptly on SIGINT/SIGTERM.
    std::thread capture_thread([&]() {
        while (g_running.load()) {
            int result = pcap_dispatch(handle, /*cnt=*/100, packet_handler,
                                        reinterpret_cast<u_char*>(&ctx));
            if (result < 0) break; // error or pcap_breakloop called
        }
    });

    // Aggregator/sender thread: once a second, flush the flow table and
    // stream each flow's features out. This thread owns all socket I/O
    // so a slow/dead Mac connection never blocks packet capture.
    std::thread sender_thread([&]() {
        while (g_running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            auto flows = flow_table.flush();
            for (const auto& [key, features] : flows) {
                sender.send_flow(key, features);
            }
        }
        // Final flush on shutdown so in-progress flows aren't lost.
        auto remaining = flow_table.flush();
        for (const auto& [key, features] : remaining) {
            sender.send_flow(key, features);
        }
    });

    capture_thread.join();
    pcap_breakloop(handle);
    sender_thread.join();

    pcap_close(handle);
    std::cerr << "[agent] shut down cleanly. total packets captured: "
               << ctx.packet_count.load() << "\n";
    return 0;
}
