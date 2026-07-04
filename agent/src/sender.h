#pragma once
#include <string>
#include "flow.h"

// Handles the TCP connection from the VM agent to the Mac listener.
// TODO(week 3): Implement connect / reconnect-on-drop / send loop.
class Sender {
public:
    Sender(const std::string& host, int port);

    // Returns false if the connection is down; caller should keep capturing
    // and retry rather than crash (see blueprint 3.1 "Signal handling").
    bool connect();

    // Serializes a FlowKey + FlowFeatures pair into the JSON contract
    // defined in docs/FLOW_SCHEMA.md and sends it over the socket.
    bool send_flow(const FlowKey& key, const FlowFeatures& features, double timestamp);

    void close();

private:
    std::string host_;
    int port_;
    int socket_fd_ = -1;
};
