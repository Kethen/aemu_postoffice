#pragma once

#include <unordered_map>
#include <vector>
#include <string>

#include <stdint.h>

/*
 * intended purpose:
 * - access control on relay, somewhat good random access would be ideal
 * - half of the data required for status page
 */

namespace aemu_postoffice_adhocctl_server {

struct snapshot_client {
	std::string mac;
	std::string ip;
	uint16_t port;
	std::string nickname;

	std::string game_code;
	std::string group_key;
};

struct snapshot_group {
	int channel;
	std::string name;
	std::vector<std::string> members;
};

struct snapshot_game {
	std::string game_code;
	std::unordered_map<std::string, struct snapshot_group> groups; // {channel}_{group_name} keyed
};

struct snapshot {
	std::unordered_map<std::string, struct snapshot_client> clients; // mac keyed
	std::unordered_map<std::string, struct snapshot_game> games; // game_code keyed
};

std::string make_group_key(int channel, std::string group_name);
struct snapshot_game &snapshot_add_game(struct snapshot &snapshot, std::string game_code);
struct snapshot_group &snapshot_add_group(struct snapshot_game &game, int channel, std::string group_name);
struct snapshot_client &snapshot_add_client(struct snapshot &snapshot, struct snapshot_game &game, struct snapshot_group &group, std::string mac, std::string ip, uint16_t port, std::string nickname);
void dump_snapshot_to_log(const struct snapshot &snapshot);

}
