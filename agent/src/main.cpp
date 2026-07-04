// Argus Capture Agent
// Entry point — opens the libpcap capture handle, starts the capture and
// sender threads, and handles clean shutdown on SIGINT/SIGTERM.
//
// Week 1 goal: get this printing a live packet count.
// Week 2 goal: wire in parser.cpp + flow.cpp for per-flow feature JSON.
// Week 3 goal: wire in sender.cpp to stream to the Mac.

#include <atomic>
#include <csignal>
#include <cstdio>
#include <pcap.h>
#include "parser.h"
#include "flow.h"
#include "sender.h"

static std::atomic<bool> running{true};

void handle_signal(int signum) {
    (void)signum;
    running = false;
}

int main(int argc, char** argv) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    char errbuf[PCAP_ERRBUF_SIZE];

    // TODO(week 1): pick device — for now, use argv[1] or list devices with pcap_findalldevs.
    const char* device = (argc > 1) ? argv[1] : nullptr;
    if (!device) {
        std::fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    std::printf("[agent] capturing on %s — Ctrl+C to stop\n", device);

    // TODO(week 1): replace this with a proper capture loop (pcap_loop or pcap_next_ex
    // in a dedicated thread), feeding packets into parse_packet() -> FlowTable -> sender.
    uint64_t packet_count = 0;
    while (running) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int rc = pcap_next_ex(handle, &header, &packet);
        if (rc == 1) {
            packet_count++;
            if (packet_count % 100 == 0) {
                std::printf("[agent] packets captured: %llu\n",
                            static_cast<unsigned long long>(packet_count));
            }
        }
    }

    std::printf("[agent] shutting down, %llu packets captured total\n",
                static_cast<unsigned long long>(packet_count));
    pcap_close(handle);
    return 0;
}
