#include <stdio.h>

#include "snapshot.h"
#include "log.h"
#include "../../server_cpp/common.h"

namespace aemu_postoffice_adhocctl_server {

struct snapshot_game &snapshot_add_game(struct snapshot &snapshot, std::string game_code){
	auto game = snapshot.games.find(game_code);
	if (game == snapshot.games.end()){
		struct snapshot_game new_game;
		new_game.game_code = game_code;
		snapshot.games.insert_or_assign(game_code, new_game);
		game = snapshot.games.find(game_code);
	}

	return game->second;
}

std::string make_group_key(int channel, std::string group_name){
	char buf[128] = {0};
	sprintf(buf, "%d_%s", channel, group_name.c_str());
	return std::string(buf);
}

struct snapshot_group &snapshot_add_group(struct snapshot_game &game, int channel, std::string group_name){
	std::string group_key = make_group_key(channel, group_name);
	auto group = game.groups.find(group_key);
	if (group == game.groups.end()){
		struct snapshot_group new_group;
		new_group.channel = channel;
		new_group.name = group_name;
		game.groups.insert_or_assign(group_key, new_group);
		group = game.groups.find(group_key);
	}

	return group->second;
}

struct snapshot_client &snapshot_add_client(struct snapshot &snapshot, struct snapshot_game &game, struct snapshot_group &group, std::string mac, std::string ip, uint16_t port, std::string nickname){
	struct snapshot_client new_client;
	new_client.mac = mac;
	new_client.ip = ip;
	new_client.port = port;
	new_client.nickname = nickname;
	new_client.game_code = game.game_code;
	new_client.group_key = make_group_key(group.channel, group.name);
	group.members.push_back(mac);

	snapshot.clients.insert_or_assign(mac, new_client);
	return snapshot.clients.find(mac)->second;
}

void dump_snapshot_to_log(const struct snapshot &snapshot){
	if (snapshot.games.size() == 0){
		return;
	}
	LOG("--- begin adhocctl snapshot dump ---\n");
	for (auto game = snapshot.games.begin();game != snapshot.games.end();game++){
		LOG("Game %s:\n", game->second.game_code.c_str());
		for (auto group = game->second.groups.begin();group != game->second.groups.end();group++){
			LOG("  Group %s channel %d:\n", group->second.name.c_str(), group->second.channel);
			for (auto member_mac : group->second.members){
				auto member_entry = snapshot.clients.find(member_mac);
				LOG("    %s: %s %s %d\n", aemu_postoffice_server::mac_bytes_to_mac_string(member_mac).c_str(), member_entry->second.nickname.c_str(), member_entry->second.ip.c_str(), member_entry->second.port);
			}
		}
	}
}

}
