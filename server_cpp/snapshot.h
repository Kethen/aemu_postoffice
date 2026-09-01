#pragma once

#include <string>
#include <vector>
#include <unordered_map>

namespace aemu_postoffice_server {

struct snapshot_client {
	std::string mac; // raw bytes
	std::string ip;
	int port;
	std::vector<int> pdp_ports;
	std::vector<int> ptp_listen_ports;
	std::vector<int> ptp_connect_ports;
	std::vector<int> ptp_accept_ports;
};

struct snapshot {
	std::unordered_map <std::string, struct snapshot_client> clients; // mac bytes keyed
};

void dump_snapshot_to_log(const struct snapshot &snapshot);

}
