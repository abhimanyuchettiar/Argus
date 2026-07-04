#include "sender.h"
#include <iostream>

// TODO(week 3): Use nlohmann/json to build the payload matching docs/FLOW_SCHEMA.md,
// then send over a POSIX TCP socket (see Beej's Guide, "Client-Server Background").
// Add reconnect logic: if send() fails, mark socket_fd_ = -1 and attempt connect()
// again on the next call rather than throwing/crashing.

Sender::Sender(const std::string& host, int port) : host_(host), port_(port) {}

bool Sender::connect() {
    // Placeholder — open socket(), connect() to host_:port_.
    std::cerr << "[sender] TODO: connect to " << host_ << ":" << port_ << "\n";
    return false;
}

bool Sender::send_flow(const FlowKey& key, const FlowFeatures& features, double timestamp) {
    (void)key;
    (void)features;
    (void)timestamp;
    // Placeholder — serialize to JSON per docs/FLOW_SCHEMA.md and write() to socket_fd_.
    return false;
}

void Sender::close() {
    // Placeholder — close(socket_fd_) if open.
}
