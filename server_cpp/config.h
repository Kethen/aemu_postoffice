#pragma once

#include <string>

#include <stdint.h>

namespace aemu_postoffice_server {

struct config {
	// -- main --
	// target packet processing tick rate
	uint64_t target_tick_interval_ms = 8;
	uint64_t target_tick_interval_idle_ms = 500;

	// ip address to bind to, will be decoded using OS provided inet_pton
	// if a v4 address is provided, the socket will only listen to v4
	// if a v6 address is provided, the socket will listen in v4 v6 mixed mode
	// used by both realy and adhocctl
	std::string ip_addr = std::string("::FFFF:0.0.0.0");


	// -- relay settings --
	// TCP port to listen to for relay
	uint16_t port = 27313;

	// number of workers for parallelized workloads
	int num_threads = 4;

	// time from client creating a tcp socket to sending init data
	// in the case of ptp connect, it also includes the window of waiting for ptp listen to show up
	uint64_t session_init_time_limit_ms = 5000;
	// how big queued send can be in userspace buffer until the session is considered as dead
	uint64_t data_queue_size_limit_byte = 512000;
	// how log ptp_connect waits for ptp_listen to respond until ptp_connect times out
	uint64_t connect_time_limit_ms = 5000;

	// maximum number of pending and active sessions before new connections are rejceted, as games tend to use multiple sockets, 4 times adhocctl limit is a good number
	int max_num_sessions = 4000;

	// restrict session creation and data communication based on data from integrated adhocctl server
	bool strict_mode = true;

	// maximum number of sessions per mac address
	int max_num_sessions_per_mac = 20;

	// -- adhocctl settings --
	// enable built-in adhocctl
	bool enable_adhocctl = true;

	// target packet processing tick rate
	uint64_t adhocctl_target_tick_interval_ms = 33;
	uint64_t adhocctl_target_tick_interval_idle_ms = 500;

	// port of adhocctl
	int adhocctl_port = 27312;

	// number of worker threads for adhocctl
	int adhocctl_num_threads = 4;

	// maximum queued send can be in userspace buffer until the adhocctl connection is considered dead
	int adhocctl_data_queue_size_limit_byte = 512000;

	// when relay only, ip addresses of clients will not be disclosed to other clients
	// this breaks p2p, but also works around a adhocctlv1 bug where single ip multiple clients causes issues on disconnect
	bool adhocctl_relay_only = true;

	// flag a client as dead after this amount of time
	uint64_t adhocctl_timeout_ms = 30000;

	// maximum number of pending and active adhocctl sessions before new connections are rejected
	int adhocctl_max_num_sessions = 1000;

	// maximum number of sessions per ip
	int adhocctl_max_num_sessions_per_ip = 16;

	// -- http status page settings --
	// http port serving the status page
	int http_status_server_port = 8888;

};

bool parse_config_from_json(std::string path, struct config &out);
void dump_config_to_log(const struct config &config);

}
