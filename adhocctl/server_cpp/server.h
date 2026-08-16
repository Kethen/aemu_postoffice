#pragma once

#include <unordered_map>
#include <thread>

#include "client.h"
#include "../../server_cpp/config.h"
#include "../../server_cpp/semaphore.h"

namespace aemu_postoffice_adhocctl_server {

enum class ServerPumpStatus {
	SUCCESS,
	ERROR,
	IDLE,
};

struct group {
	int channel;
	std::string name; // channel is not prefixed here
	std::string leader_mac;
	std::unordered_map<std::string, Client *> members; // client keyed with mac address
};

struct game {
	std::unordered_map<std::string, group> groups; // with {channel}_{name} as the key
};

class Server {
	public:
		Server(aemu_postoffice_server::Config config);
		~Server();

		ServerPumpStatus pump();

	private:
		std::unordered_map<std::string, Client> pending_clients; // clients that have connected but not logged in, keyed with {ip:port}
		std::unordered_map<std::string, Client> clients; // logged in clients, keyed with mac address bytes

		bool stopping;
		std::vector<std::thread> pending_clients_workers;
		std::vector<std::vector<Client *>>pending_client_work_queues;
		std::vector<std::vector<std::string>> pending_clients_to_remove;
		std::vector<std::vector<std::string>> pending_clients_to_upgrade;
		std::vector<Semaphore> pending_clients_worker_start_sema;
		std::vector<Semaphore> pending_clients_worker_finish_sema;

		std::vector<std::thread> clients_recv_workers;
		std::vector<std::vector<struct group*>> client_recv_work_queue;
		std::vector<std::vector<std::string>> clients_to_remove;
		std::vector<std::vector<struct client_op>> client_connect_disconnect_ops;
		std::vector<Semaphore> clients_recv_worker_start_sema;
		std::vector<Semaphore> clients_recv_worker_finish_sema;

		std::vector<std::thread> clients_send_workers;
		std::vector<std::vector<Client *>>client_send_work_queue;
		std::vector<Semaphore> clients_send_worker_start_sema;
		std::vector<Semaphore> clients_send_worker_finish_sema;

		// the grouping tree
		std::unordered_map<std::string, game> games;
		aemu_postoffice_server::Config config;
		int sock_fd;

		void disconnect_client(std::string mac);
		void remove_client(std::string mac);
		void connect_client(std::string mac, std::string group_name, bool groupless_group);
};

/* server loop
 * 1. check for new connections, spawn new clients into pending while evicting duplicates
 * 2. pump client to server operations from clients in worker threads, scheduled by individual clients
 * 3. process login operations from pending clients to promote clients into game's default gruop and remove timed out clients in main thread
 * 3. perform client to server operations in worker threads except for group modifying operations, scheduled by group
 * 4. process group modifying operations and remove dead clients in main thread
 * 5. pump server to client operations in worker threads, scheduled by individual clients
 */

}
