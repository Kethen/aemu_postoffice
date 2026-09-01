#include "snapshot.h"
#include "log.h"
#include "common.h"

namespace aemu_postoffice_server {

void dump_snapshot_to_log(const struct snapshot &snapshot){
	LOG("--- begin snapshot dump ---\n");
	for (auto client = snapshot.clients.begin();client != snapshot.clients.end();client++){
		LOG("%s:\n", mac_bytes_to_mac_string(client->second.mac).c_str());
		LOG("  addr: %s %d\n", client->second.ip.c_str(), client->second.port);
		LOG("  pdp_ports: ");
		for (auto &pdp_port : client->second.pdp_ports){
			LOG("%d ", pdp_port);
		}
		LOG("\n");
		LOG("  ptp_listen_ports: ");
		for (auto &ptp_listen_port : client->second.ptp_listen_ports){
			LOG("%d ", ptp_listen_port);
		}
		LOG("\n");
		LOG("  ptp_connect_ports: ");
		for (auto &ptp_connect_port : client->second.ptp_connect_ports){
			LOG("%d ", ptp_connect_port);
		}
		LOG("\n");
		LOG("  ptp_accept_ports: ");
		for (auto &ptp_accept_port : client->second.ptp_accept_ports){
			LOG("%d ", ptp_accept_port);
		}
		LOG("\n");
	}
}

}
