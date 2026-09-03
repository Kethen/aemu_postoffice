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
#include <vector>

#ifdef __unix__
#include <signal.h>
#include <sys/resource.h>
#include <sys/errno.h>
#endif

#include "server.h"
#include "log.h"
#include "../adhocctl/server_cpp/server.h"
#include "http_status_server.h"

#ifdef __unix__
// for naming threads
#include <pthread.h>
#endif

static void set_thread_name(std::string name){
	#if __unix__
	pthread_t tid = pthread_self();
	pthread_setname_np(tid, name.c_str());
	#else
	// hm, what do
	#endif
}

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

	struct aemu_postoffice_server::config config;
	struct aemu_postoffice_adhocctl_server::game_db game_db;

	auto parse_config_and_game_db = [&config, &game_db] () -> bool {
		bool config_parse_result = aemu_postoffice_server::parse_config_from_json("./config.json", config);
		if (!config_parse_result){
			aemu_postoffice_server::LOG("%s: config parse failed\n", __func__);
			return false;
		}

		bool game_db_parse_result = aemu_postoffice_adhocctl_server::parse_game_db_from_json("./game_db.json", game_db);
		if (!game_db_parse_result){
			aemu_postoffice_server::LOG("%s: game db parsing failed!\n", __func__);
			return false;
		}
		return true;
	};

	if (!parse_config_and_game_db()){
		exit(1);
	}

	#ifdef __unix__
	static const int buffer_fds = 100;
	static const int http_fds = 1000;
	int file_limit = config.max_num_sessions + config.adhocctl_max_num_sessions + buffer_fds + http_fds;
	struct rlimit num_file_limit = {
		(rlim_t)file_limit,
		(rlim_t)file_limit
	};
	int set_limit_status = setrlimit(RLIMIT_NOFILE, &num_file_limit);
	if (set_limit_status == -1){
		aemu_postoffice_server::LOG("%s: failed changing number of opened files (including sockets) limit, 0x%x\n", __func__, errno);
	}
	#endif

	std::vector<std::thread> threads;

	aemu_postoffice_server::Server server(config);
	std::mutex relay_mutex;
	aemu_postoffice_adhocctl_server::Server *adhocctl_server = NULL;
	std::mutex adhocctl_mutex;
	aemu_postoffice_server::HttpStatusServer *http_status_server = NULL;
	std::mutex http_status_server_mutex;

	threads.emplace_back([&config, &server, &relay_mutex, &http_status_server, &http_status_server_mutex] {
		set_thread_name("relay main");

		auto last_dump = std::chrono::high_resolution_clock::now();
		while(!should_stop){
			auto begin = std::chrono::high_resolution_clock::now();
			relay_mutex.lock();
			aemu_postoffice_server::ServerPumpStatus pump_status = server.pump();
			relay_mutex.unlock();
			uint64_t interval_ms = config.target_tick_interval_ms;
			if (pump_status == aemu_postoffice_server::ServerPumpStatus::IDLE){
				interval_ms = config.target_tick_interval_idle_ms;
				if (http_status_server != NULL){
					http_status_server_mutex.lock();
					http_status_server->update_relay_snapshot(aemu_postoffice_server::snapshot());
					http_status_server_mutex.unlock();
				}
			} else if (pump_status == aemu_postoffice_server::ServerPumpStatus::LISTEN_SOCK_DEAD){
				should_stop = true;
				break;
			} else if (pump_status == aemu_postoffice_server::ServerPumpStatus::SUCCESS) {
				if ((begin - last_dump) / std::chrono::seconds(1) >= 5) {
					last_dump = begin;
					struct aemu_postoffice_server::snapshot snapshot = server.get_snapshot();
					//aemu_postoffice_server::dump_snapshot_to_log(snapshot);
					if (http_status_server != NULL){
						http_status_server_mutex.lock();
						http_status_server->update_relay_snapshot(snapshot);
						http_status_server_mutex.unlock();
					}
				}
			}
			auto timespent = std::chrono::high_resolution_clock::now() - begin;
			int64_t wait_ms = config.target_tick_interval_ms - timespent / std::chrono::milliseconds(1);
			if (wait_ms > 0){
				std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
			}
		}
	});

	if (config.enable_adhocctl){
		adhocctl_server = new aemu_postoffice_adhocctl_server::Server(config, game_db);
		http_status_server = new aemu_postoffice_server::HttpStatusServer(config, game_db);

		threads.emplace_back([&config, &adhocctl_server, &relay_mutex, &server, &adhocctl_mutex, &http_status_server, &http_status_server_mutex] {
			set_thread_name("adhocctl main");

			auto last_dump = std::chrono::high_resolution_clock::now();
			auto last_sync = std::chrono::high_resolution_clock::now();
			while(!should_stop){
				auto begin = std::chrono::high_resolution_clock::now();

				adhocctl_mutex.lock();
				aemu_postoffice_adhocctl_server::ServerPumpStatus pump_status = adhocctl_server->pump();
				adhocctl_mutex.unlock();
				uint64_t interval_ms = config.adhocctl_target_tick_interval_ms;
				if (pump_status == aemu_postoffice_adhocctl_server::ServerPumpStatus::IDLE){
					interval_ms = config.adhocctl_target_tick_interval_idle_ms;
					if (http_status_server != NULL){
						http_status_server_mutex.lock();
						http_status_server->update_adhocctl_snapshot(aemu_postoffice_adhocctl_server::snapshot());
						http_status_server_mutex.unlock();
					}
				} else if (pump_status == aemu_postoffice_adhocctl_server::ServerPumpStatus::ERROR){
					should_stop = true;
					break;
				} else if (pump_status == aemu_postoffice_adhocctl_server::ServerPumpStatus::SUCCESS){
					auto snapshot = adhocctl_server->get_snapshot();
					if ((begin - last_dump) / std::chrono::seconds(1) >= 5){
						last_dump = begin;
						//aemu_postoffice_adhocctl_server::dump_snapshot_to_log(snapshot);
						if (http_status_server != NULL){
							http_status_server_mutex.lock();
							http_status_server->update_adhocctl_snapshot(snapshot);
							http_status_server_mutex.unlock();
						}
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

		threads.emplace_back([&http_status_server, &http_status_server_mutex] {
			set_thread_name("status watchdog");

			while(!should_stop){
				{
					std::lock_guard<std::mutex> lg(http_status_server_mutex);
					if (!http_status_server->is_server_running()){
						should_stop = true;
						break;
					}
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
			}
		});
	}

	threads.emplace_back([&server, &relay_mutex, &adhocctl_server, &adhocctl_mutex, &http_status_server, &http_status_server_mutex, &config, &game_db, &parse_config_and_game_db] () {
		set_thread_name("config reload");

		auto last_parse = std::chrono::high_resolution_clock::now();
		while(!should_stop){
			auto now = std::chrono::high_resolution_clock::now();
			if ((now - last_parse) / std::chrono::seconds(1) < 5){
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
				continue;
			}

			last_parse = now;
			if (!parse_config_and_game_db()){
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
				continue;
			}

			relay_mutex.lock();
			server.set_config(config);
			relay_mutex.unlock();
			if (adhocctl_server != NULL){
				adhocctl_mutex.lock();
				adhocctl_server->set_config(config);
				adhocctl_server->set_game_db(game_db);
				adhocctl_mutex.unlock();
			}
			if (http_status_server != NULL){
				http_status_server_mutex.lock();
				http_status_server->set_game_db(game_db);
				http_status_server_mutex.unlock();
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(250));
		}
	});

	for (auto &thread : threads){
		thread.join();
	}
	if (adhocctl_server != NULL){
		delete(adhocctl_server);
	}
	if (http_status_server != NULL){
		delete(http_status_server);
	}

	aemu_postoffice_server::LOG("%s: server stopped\n", __func__);

	return 0;
}
