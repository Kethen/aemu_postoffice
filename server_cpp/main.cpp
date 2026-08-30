#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// mingw-w64 only on windows, not available in msvc
#include <libgen.h>
#include <unistd.h>

#include <chrono>
#include <thread>
#include <mutex>

#ifdef __unix__
#include <signal.h>
#include <sys/resource.h>
#include <sys/errno.h>
#endif

#include "server.h"
#include "log.h"
#include "../adhocctl/server_cpp/server.h"

bool should_stop = false;

#ifdef __unix__
void handle_sigterm(int signum){
	aemu_postoffice_server::LOG("%s: terminating\n", __func__);
	should_stop = true;
}
#endif

int main(int argc, char **argv){
	#ifdef __unix__
	signal(SIGTERM, handle_sigterm);
	signal(SIGINT, handle_sigterm);
	#endif

	char exe_path[strlen(argv[0]) + 1] = {0};
	strcpy(exe_path, argv[0]);
	dirname(exe_path);
	chdir(exe_path);

	{
		struct aemu_postoffice_server::config config;
		aemu_postoffice_server::Server server(config);
		std::mutex relay_mutex;

		#ifdef __unix__
		struct rlimit num_file_limit = {
			(rlim_t)(config.max_num_sessions + 10),
			(rlim_t)(config.max_num_sessions + 10)
		};
		int set_limit_status = setrlimit(RLIMIT_NOFILE, &num_file_limit);
		if (set_limit_status == -1){
			aemu_postoffice_server::LOG("%s: failed changing number of opened files (including sockets) limit, 0x%x\n", __func__, errno);
		}
		#endif

		auto relay_thread = std::thread([&config, &server, &relay_mutex] {
			while(!should_stop){
				auto begin = std::chrono::high_resolution_clock::now();
				relay_mutex.lock();
				aemu_postoffice_server::ServerPumpStatus pump_status = server.pump();
				relay_mutex.unlock();
				uint64_t interval_ms = config.target_tick_interval_ms;
				if (pump_status == aemu_postoffice_server::ServerPumpStatus::IDLE){
					interval_ms = config.target_tick_interval_idle_ms;
				} else if (pump_status == aemu_postoffice_server::ServerPumpStatus::LISTEN_SOCK_DEAD){
					break;
				}
				auto timespent = std::chrono::high_resolution_clock::now() - begin;
				int64_t wait_ms = config.target_tick_interval_ms - timespent / std::chrono::milliseconds(1);
				if (wait_ms > 0){
					std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
				}
			}
		});

		if (config.enable_adhocctl){
			struct aemu_postoffice_adhocctl_server::game_db game_db;
			bool parse_result = aemu_postoffice_adhocctl_server::parse_game_db_from_json("./game_db.json", game_db);
			if (!parse_result){
				aemu_postoffice_server::LOG("%s: game db parsing failed!\n", __func__);
				exit(1);
			}
			aemu_postoffice_adhocctl_server::Server adhocctl_server(config, game_db);

			auto adhocctl_thread = std::thread([&config, &adhocctl_server, &relay_mutex, &server] {
				auto last_dump = std::chrono::high_resolution_clock::now();
				auto last_sync = std::chrono::high_resolution_clock::now();
				while(!should_stop){
					auto begin = std::chrono::high_resolution_clock::now();

					aemu_postoffice_adhocctl_server::ServerPumpStatus pump_status = adhocctl_server.pump();
					uint64_t interval_ms = config.adhocctl_target_tick_interval_ms;
					if (pump_status == aemu_postoffice_adhocctl_server::ServerPumpStatus::IDLE){
						interval_ms = config.adhocctl_target_tick_interval_idle_ms;
					} else if (pump_status == aemu_postoffice_adhocctl_server::ServerPumpStatus::ERROR){
						break;
					} else if (pump_status == aemu_postoffice_adhocctl_server::ServerPumpStatus::SUCCESS){
						auto snapshot = adhocctl_server.get_snapshot();
						if ((begin - last_dump) / std::chrono::seconds(1) >= 5){
							last_dump = begin;
							aemu_postoffice_adhocctl_server::dump_snapshot_to_log(snapshot);
						}
						relay_mutex.lock();
						server.update_adhocctl_data(snapshot);
						relay_mutex.unlock();
					}
					auto timespent = std::chrono::high_resolution_clock::now() - begin;
					int64_t wait_ms = config.target_tick_interval_ms - timespent / std::chrono::milliseconds(1);
					if (wait_ms > 0){
						std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
					}
				}
			});

			adhocctl_thread.join();
		}

		relay_thread.join();
	}

	aemu_postoffice_server::LOG("%s: server stopped\n", __func__);

	return 0;
}
