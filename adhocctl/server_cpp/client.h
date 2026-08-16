#pragma once

#include <stdint.h>

#include <string>
#include <vector>
#include <chrono>

#include "../../server_cpp/config.h"

namespace aemu_postoffice_adhocctl_server {

const static int V1_PROTOCOL_DEFAULT_CHANNEL = 11;

// client -> server operations that happens outside of the client
enum class ClientOp {
	CONNECT,
	CHAT,
	SCAN,
	DISCONNECT,
};

struct connect_op {
	int channel;
	std::string group;
};

struct chat_op {
	std::string msg;
};

struct scan_op{
};

struct disconnect_op{
	int channel;
};

struct destroy_op{
};

struct client_op {
	std::string mac;
	ClientOp op;
	connect_op connect;
	chat_op chat;
	scan_op scan;
	disconnect_op disconnect;
	destroy_op destroy;
};

enum class ClientPumpStatus {
	SUCCESS,
	DISCONNECT,
	ERROR,
	OVERFLOW,
	TIMEDOUT, // happens when a client has not logged in for too long, or when a client has not been sending data
};

enum class ServerToClientOpQueueStatus {
	SUCCESS,
	OVERFLOW,
};

class Client {
	public:
		Client(int sock_fd, std::string ip, uint16_t port, std::string socket_name, int protocol_revision, aemu_postoffice_server::Config *config);
		void close_socket();
		~Client();

		// server -> client operations, will be queued into send buf, then send on pump
		ServerToClientOpQueueStatus connect_ack(std::string group_mac);
		ServerToClientOpQueueStatus disconnect_notify(Client *peer);
		ServerToClientOpQueueStatus chat(std::string nickname, std::string msg);
		ServerToClientOpQueueStatus scan_result(std::string group_name, std::string leader_mac);
		ServerToClientOpQueueStatus scan_complete();
		ServerToClientOpQueueStatus connect_notify(Client *peer);

		ClientPumpStatus pump_from_client(); // put client operations into a vector, which can be fetched using get_client_ops
		ClientPumpStatus pump_to_client(); // push server -> client operations to clients

		std::string get_ip();
		uint16_t get_port;
		std::string get_socket_name();
		bool is_logged_in();
		std::string get_mac();
		std::string get_nickname();
		int get_channel();
		int get_protocol_revision();
		void get_client_ops(std::vector<client_op> &container);

		// for seeking client in group tree, used externally
		std::string group; // group id with channel prefixed
		uint32_t id; // in adhocctlv1 p2p mode: ipv4, in adhocctlv1 relay mode: unique id
		std::string game_code;

	private:
		int sock_fd;
		std::string ip;
		uint16_t port;
		std::string socket_name;
		int protocol_revision;
		aemu_postoffice_server::Config *config;
		int channel;

		bool logged_in;
		std::string mac;
		std::string nickname;
		std::string recv_buf;
		std::string send_buf;
		std::vector<client_op> client_ops;

		std::chrono::high_resolution_clock::time_point create_time;
		std::chrono::high_resolution_clock::time_point last_seen;

		ClientPumpStatus process_recv_buf_v1();
};

}
