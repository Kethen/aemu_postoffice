#include <stdint.h>
#include <stdlib.h>

#include <chrono>
#include <thread>

#ifdef __unix__
#include <signal.h>
#endif

#include "server.h"
#include "log.h"

bool should_stop = false;

#ifdef __unix__
void handle_sigterm(int signum){
	should_stop = true;
}
#endif

int main(){
	#ifdef __unix__
	signal(SIGTERM, handle_sigterm);
	signal(SIGINT, handle_sigterm);
	#endif

	{
		Config config;
		Server server(config);

		while(!should_stop){
			auto begin = std::chrono::high_resolution_clock::now();
			ServerPumpStatus pump_status = server.pump();
			if (pump_status != ServerPumpStatus::SUCCESS){
				exit(1);
			}
			auto timespent = std::chrono::high_resolution_clock::now() - begin;
			int64_t wait_ms = config.target_tick_interval_ms - timespent / std::chrono::milliseconds(1);
			if (wait_ms > 0){
				std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
			}
		}
	}

	LOG("%s: server stopped\n", __func__);

	return 0;
}
