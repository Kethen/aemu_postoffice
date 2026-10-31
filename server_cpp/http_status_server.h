// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <string>
#include <mutex>
#include <thread>
#include <vector>

#include "snapshot.h"
#include "../adhocctl/server_cpp/snapshot.h"
#include "config.h"
#include "../adhocctl/server_cpp/game_db.h"

namespace aemu_postoffice_server {

class HttpStatusServer {
	public:
		HttpStatusServer(const struct config &config, const struct aemu_postoffice_adhocctl_server::game_db &game_db);
		~HttpStatusServer();
		void update_adhocctl_snapshot(const struct aemu_postoffice_adhocctl_server::snapshot &snapshot);
		void update_relay_snapshot(const struct snapshot &snapshot);
		void set_game_db(const struct aemu_postoffice_adhocctl_server::game_db &game_db);
		void set_config(const struct config &config);

		bool is_server_running();
		// currently it is not possible to dynamically change status page related configurations

	private:
		struct config config;
		std::mutex config_mutex;
		struct snapshot relay_snapshot;
		std::mutex relay_snapshot_mutex;
		struct aemu_postoffice_adhocctl_server::snapshot adhocctl_snapshot;
		std::mutex adhocctl_snapshot_mutex;
		struct aemu_postoffice_adhocctl_server::game_db game_db;
		std::mutex game_db_mutex;

		void *server_impl;
		std::thread *server_thread;
		bool server_running;

		std::string crunched_snapshot;
		std::mutex crunched_snapshot_mutex;
		std::string crunched_metadata;
		std::mutex crunched_metadata_mutex;
		std::thread *data_crunch_thread;
		bool stopping;
};

}
