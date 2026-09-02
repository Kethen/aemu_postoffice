#include "http_status_server.h"

#include "../ext/cpp-httplib/httplib.h"
#include "../ext/json/json.hpp"
#include "log.h"
#include "file_util.h"

#include <chrono>

#ifdef __unix__
// for naming threads
#include <pthread.h>
#endif

#include <stdio.h>

static const std::string HTTP_ASSET_PATH("./http_assets/");

namespace aemu_postoffice_server {

static void set_thread_name(std::string name){
	#if __unix__
	pthread_t tid = pthread_self();
	pthread_setname_np(tid, name.c_str());
	#else
	// hm, what do
	#endif
}

HttpStatusServer::HttpStatusServer(const struct config &config, const struct aemu_postoffice_adhocctl_server::game_db &game_db){
	this->game_db = game_db;

	data_crunch_thread = new std::thread([this] () {
		set_thread_name("status prep");
		auto last_crunch = std::chrono::high_resolution_clock::now();

		while(!this->stopping){
			auto now = std::chrono::high_resolution_clock::now();
			if ((now - last_crunch) / std::chrono::seconds(1) < 5){
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
				continue;
			}

			last_crunch = now;

			relay_snapshot_mutex.lock();
			auto relay_snapshot_copy = relay_snapshot;
			relay_snapshot_mutex.unlock();

			adhocctl_snapshot_mutex.lock();
			auto adhocctl_snapshot_copy = adhocctl_snapshot;
			adhocctl_snapshot_mutex.unlock();

			game_db_mutex.lock();
			auto game_db_copy = this->game_db;
			game_db_mutex.unlock();

			nlohmann::json output = {};
			output["games"] = nlohmann::json::array();
			for (auto game = adhocctl_snapshot_copy.games.begin();game != adhocctl_snapshot_copy.games.end();game++){
				nlohmann::json game_entry = {};
				game_entry["game_ids"] = nlohmann::json::array();
				game_entry["game_ids"].push_back(game->second.game_code);
				for (auto crosslink = game_db_copy.crosslinks.begin();crosslink != game_db_copy.crosslinks.end();crosslink++){
					if (crosslink->second == game->second.game_code){
						game_entry["game_ids"].push_back(crosslink->first);
					}
				}

				auto game_name = game_db_copy.names.find(game->second.game_code);
				if (game_name != game_db_copy.names.end()){
					game_entry["name"] = game_name->second;
				} else {
					game_entry["name"] = game->second.game_code;
				}

				game_entry["usercount"] = 0;
				game_entry["groups"] = nlohmann::json::array();
				for (auto group = game->second.groups.begin();group != game->second.groups.end();group++){
					int game_user_count = game_entry["usercount"];
					game_entry["usercount"] = game_user_count + group->second.members.size();

					// current data.json format does not contain groupless user data
					if (group->second.channel > 0){
						nlohmann::json group_entry = {};
						group_entry["name"] = group->second.name;
						group_entry["channel"] = group->second.channel;
						group_entry["usercount"] = group->second.members.size();

						group_entry["users"] = nlohmann::json::array();
						for (auto &member : group->second.members){
							nlohmann::json user_entry = {};
							user_entry["name"] = adhocctl_snapshot_copy.clients[member].nickname;
							user_entry["pdp_ports"] = nlohmann::json::array();
							user_entry["ptp_ports"] = nlohmann::json::array();

							auto client = relay_snapshot_copy.clients.find(member);
							if (client != relay_snapshot_copy.clients.end()){
								for (auto pdp_port : client->second.pdp_ports){
									user_entry["pdp_ports"].push_back(pdp_port);
								}
								for (auto ptp_listen_port : client->second.ptp_listen_ports){
									user_entry["ptp_ports"].push_back(ptp_listen_port);
								}
								for (auto ptp_connect_port : client->second.ptp_connect_ports){
									user_entry["ptp_ports"].push_back(ptp_connect_port);
								}
							}

							group_entry["users"].push_back(user_entry);
						}

						game_entry["groups"].push_back(group_entry);
					}
				}

				output["games"].push_back(game_entry);
			}

			std::string output_string = output.dump();
			crunched_snapshot_mutex.lock();
			crunched_snapshot = output_string;
			crunched_snapshot_mutex.unlock();

			std::this_thread::sleep_for(std::chrono::milliseconds(250));
		}
	});

	httplib::Server *server = new httplib::Server();
	server_impl = server;

	server->set_mount_point("/assets", HTTP_ASSET_PATH);
	server->Get("/data.json", [this] (const httplib::Request &req, httplib::Response &res) {
		crunched_snapshot_mutex.lock();
		std::string output = crunched_snapshot;
		crunched_snapshot_mutex.unlock();
		res.status = 200;
		res.set_content(output, "application/json;charset=UTF-8");
		res.set_header("Access-Control-Allow-Origin", "*");
	});

	server->Get("/", [] (const httplib::Request &req, httplib::Response &res) {
		char path_buf[1024] = {0};
		sprintf(path_buf, "%s%s", HTTP_ASSET_PATH.c_str(), "status.html");
		std::string file_path = std::string(path_buf);
		std::string raw_bytes = read_file_to_string(file_path);
		if (raw_bytes == std::string("")){
			res.status = 400;
			res.set_content("status.html is missing...", "text/plain");
			return;
		}
		res.status = 200;
		res.set_content(raw_bytes, "text/html;charset=UTF-8");
	});

	server_running = true;
	stopping = false;

	server_thread = new std::thread([this, server, config] () {
		set_thread_name("http status");
		server->listen(config.ip_addr, config.http_status_server_port);
		server_running = false;
	});
}

HttpStatusServer::~HttpStatusServer(){
	stopping = true;

	httplib::Server *server = (httplib::Server *)server_impl;

	server->stop();
	server_thread->join();
	delete(server_thread);
	delete(server);

	data_crunch_thread->join();
	delete(data_crunch_thread);
}

void HttpStatusServer::update_relay_snapshot(const struct snapshot &snapshot){
	relay_snapshot_mutex.lock();
	relay_snapshot = snapshot;
	relay_snapshot_mutex.unlock();
}

void HttpStatusServer::update_adhocctl_snapshot(const struct aemu_postoffice_adhocctl_server::snapshot &snapshot){
	adhocctl_snapshot_mutex.lock();
	adhocctl_snapshot = snapshot;
	adhocctl_snapshot_mutex.unlock();
}

void HttpStatusServer::set_game_db(const struct aemu_postoffice_adhocctl_server::game_db &game_db){
	game_db_mutex.lock();
	this->game_db = game_db;
	game_db_mutex.unlock();
}

bool HttpStatusServer::is_server_running(){
	return server_running;
}

}
