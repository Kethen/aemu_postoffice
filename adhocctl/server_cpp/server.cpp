#ifdef __unix__
#include <pthread.h>
#endif

#include "server.h"
#include "client.h"
#include "common.h"
#include "log.h"
#include "../../server_cpp/native_socket.h"

using namespace aemu_postoffice_server;

namespace aemu_postoffice_adhocctl_server{

static void set_thread_name(std::string name){
	#if __unix__
	pthread_t tid = pthread_self();
	pthread_setname_np(tid, name.c_str());
	#else
	// hm, what do
	#endif
}

Server::Server(aemu_postoffice_server::Config config){
	this->config = config;

	switch (get_addr_family(config.ip_addr)){
		case AddrFamily::IPV6:
			LOG("%s: starting adhocctl server in ipv4 ipv6 mixed mode, P2P is current NOT supported, only relay mode is supported\n", __func__);
			config.adhocctl_relay_only = true;
			break;
		case AddrFamily::IPV4:
			LOG("%s: starting adhocctl server in ipv4 mode\n", __func__);
			break;
		case AddrFamily::UNKNOWN:
			LOG("%s: invalid address %s, not starting adhocctl server\n", __func__, config.ip_addr.c_str());
			sock_fd = -3;
			return;
			break;
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			exit(1);
			break;
	}

	sock_fd = native_tcp_listen(config.ip_addr, config.adhocctl_port);
	if (sock_fd == -1){
		LOG("%s: failed creating socket, 0x%x\n", __func__, native_get_last_socket_error());
		return;
	}
	if (sock_fd == -2){
		LOG("%s: failed parsing %s as ipv4 nor ipv6\n", __func__, config.ip_addr.c_str());
		return;
	}

	stopping = false;

	for (int i = 0;i < config.adhocctl_num_threads;i++){
		pending_clients_worker_start_sema.push_back(Semaphore());
		pending_clients_worker_finish_sema.push_back(Semaphore());
		clients_recv_worker_start_sema.push_back(Semaphore());
		clients_recv_worker_finish_sema.push_back(Semaphore());
		clients_send_worker_start_sema.push_back(Semaphore());
		clients_send_worker_finish_sema.push_back(Semaphore());
	}

	for (int i = 0;i < config.adhocctl_num_threads;i++){
		this->pending_client_work_queues.push_back(std::vector<Client *>());
		this->pending_clients_to_remove.push_back(std::vector<std::string>());
		this->pending_clients_to_upgrade.push_back(std::vector<std::string>());
		pending_clients_workers.push_back(std::thread([this, i]{
			char thread_name_buf[128] = {0};
			sprintf(thread_name_buf, "adhocctl_%d", i);
			set_thread_name(std::string(thread_name_buf));

			while(true){
				this->pending_clients_worker_start_sema[i].acquire();

				if (this->stopping){
					break;
				}

				for (Client *c : this->pending_client_work_queues[i]){
					ClientPumpStatus pump_status = c->pump_from_client();
					if (pump_status != ClientPumpStatus::SUCCESS){
						this->pending_clients_to_remove[i].push_back(c->get_socket_name());
						continue;
					}
					if (c->is_logged_in()){
						this->pending_clients_to_upgrade[i].push_back(c->get_socket_name());
					}
				}

				this->pending_clients_worker_finish_sema[i].release();
			}
		}));

		client_recv_work_queue.push_back(std::vector<struct group*>());
		clients_to_remove.push_back(std::vector<std::string>());
		client_connect_disconnect_ops.push_back(std::vector<client_op>());
		clients_recv_workers.push_back(std::thread([this, i]{
			char thread_name_buf[128] = {0};
			sprintf(thread_name_buf, "adhocctl_recv_%d", i);
			set_thread_name(std::string(thread_name_buf));

			while(true){
				this->clients_recv_worker_start_sema[i].acquire();

				if (this->stopping){
					break;
				}

				for (auto &group : this->client_recv_work_queue[i]){
					auto first_member = group->members.begin();
					auto game = games.find(first_member->second->game_code);

					for (auto client = group->members.begin();client != group->members.end();client++){
						ClientPumpStatus pump_status = client->second->pump_from_client();
						if (pump_status != ClientPumpStatus::SUCCESS){
							this->clients_to_remove[i].push_back(client->first);
							continue;
						}

						std::vector<client_op> ops;
						client->second->get_client_ops(ops);

						for (auto &op : ops){
							ServerToClientOpQueueStatus queue_status;
							if (op.op == ClientOp::CONNECT || op.op == ClientOp::DISCONNECT){
								this->client_connect_disconnect_ops[i].push_back(op);
							} else if (op.op == ClientOp::SCAN){
								for (auto g = game->second.groups.begin();g != game->second.groups.end();g++){
									if (g->second.channel < 0){
										continue;
									}
									queue_status = client->second->scan_result(g->second.name, g->second.leader_mac);
									if (queue_status != ServerToClientOpQueueStatus::SUCCESS){
										this->clients_to_remove[i].push_back(client->first);
									}
								}
								queue_status = client->second->scan_complete();
								if (queue_status != ServerToClientOpQueueStatus::SUCCESS){
									this->clients_to_remove[i].push_back(client->first);
								}
							} else if (op.op == ClientOp::CHAT){
								if (group->channel < 0){
									continue;
								}
								for (auto m = group->members.begin();m != group->members.end();m++){
									if (m->first == client->first){
										continue;
									}
									queue_status = m->second->chat(client->second->get_nickname(), op.chat.msg);
									if (queue_status != ServerToClientOpQueueStatus::SUCCESS){
										this->clients_to_remove[i].push_back(client->first);
									}
								}
							} else {
								LOG("%s: unreachable code path, debug this\n", __func__);
								exit(1);
							}
						}
					}
				}

				this->clients_recv_worker_finish_sema[i].release();
			}
		}));

		client_send_work_queue.push_back(std::vector<Client *>());
		clients_send_workers.push_back(std::thread([this, i]{
			char thread_name_buf[128] = {0};
			sprintf(thread_name_buf, "adhocctl_send_%d", i);
			set_thread_name(std::string(thread_name_buf));

			while(true){
				this->clients_send_worker_start_sema[i].acquire();

				if (this->stopping){
					break;
				}

				for (auto &client : client_send_work_queue[i]){
					ClientPumpStatus pump_status = client->pump_to_client();
					if (pump_status != ClientPumpStatus::SUCCESS){
						this->clients_to_remove[i].push_back(client->get_mac());
					}
				}

				this->clients_send_worker_finish_sema[i].release();
			}
		}));
	}
}

Server::~Server(){
	// cleanup threads
	stopping = true;
	for (int i = 0;i < config.adhocctl_num_threads;i++){
		pending_clients_worker_start_sema[i].release();
		clients_recv_worker_start_sema[i].release();
		clients_send_worker_start_sema[i].release();
	}
	for (int i = 0;i < config.adhocctl_num_threads;i++){
		pending_clients_workers[i].join();
		clients_recv_workers[i].join();
		clients_send_workers[i].join();
	}

	// close client sockets
	for (auto client = clients.begin();client != clients.end();client++){
		client->second.close_socket();
	}

	// close listen socket
	native_close(sock_fd);
}

void Server::disconnect_client(std::string mac){
	auto target = clients.find(mac);
	if (target == clients.end()){
		return;
	}
	std::string group_key = target->second.group;
	target->second.group = std::string("");
	auto game = games.find(target->second.game_code);
	if (game == games.end()){
		return;
	}
	auto group = game->second.groups.find(group_key);
	if (group == game->second.groups.end()){
		return;
	}
	auto member = group->second.members.find(mac);
	if (member == group->second.members.end()){
		return;
	}
	group->second.members.erase(member);
	if (group->second.channel >= 1){
		for (auto member = group->second.members.begin();member != group->second.members.end();member++){
			ServerToClientOpQueueStatus queue_status = member->second->disconnect_notify(&target->second);
			if (queue_status != ServerToClientOpQueueStatus::SUCCESS){
				clients_to_remove[0].push_back(member->second->get_mac());
			}
		}
	}
	if (group->second.members.size() == 0){
		game->second.groups.erase(group);
	}
	if (game->second.groups.size() == 0){
		games.erase(game);
	}
}

void Server::remove_client(std::string mac){
	auto target = clients.find(mac);
	if (target == clients.end()){
		return;
	}
	disconnect_client(mac);
	target->second.close_socket();
	clients.erase(target);
}

static std::string make_group_key(int channel, std::string group_name){
	char buf[128] = {0};
	sprintf(buf, "%d_%s", channel, group_name.c_str());
	return std::string(buf);
}

void Server::connect_client(std::string mac, std::string group_name, bool groupless_group){
	disconnect_client(mac);
	auto target = clients.find(mac);
	std::string game_code = target->second.game_code;

	// TODO resolve cross linking here and update the client's game code

	auto game = games.find(game_code);

	if (game == games.end()){
		struct game new_game = {};
		games[game_code] = new_game;
		game = games.find(game_code);
	}

	int channel = target->second.get_channel();
	if (groupless_group) {
		channel = channel * -1;
	}
	std::string group_key = make_group_key(channel, group_name);
	auto group = game->second.groups.find(group_key);
	if (group == game->second.groups.end()){
		struct group new_group = {};
		new_group.channel = channel;
		new_group.name = group_name;
		new_group.leader_mac = mac;
		game->second.groups[group_key] = new_group;
		group = game->second.groups.find(group_key);
	}

	if (!groupless_group){
		ServerToClientOpQueueStatus queue_status;
		for (auto member = group->second.members.begin(); member != group->second.members.end(); member++){
			queue_status = member->second->connect_notify(&target->second);
			if (queue_status != ServerToClientOpQueueStatus::SUCCESS){
				clients_to_remove[0].push_back(member->second->get_mac());
			}
			queue_status = target->second.connect_notify(member->second);
			if (queue_status != ServerToClientOpQueueStatus::SUCCESS){
				clients_to_remove[0].push_back(target->second.get_mac());
			}
		}
		queue_status = target->second.connect_ack(group->second.leader_mac);
		if (queue_status != ServerToClientOpQueueStatus::SUCCESS){
			clients_to_remove[0].push_back(target->second.get_mac());
		}
	}

	group->second.members[mac] = &target->second;
	target->second.group = group_key;
}

ServerPumpStatus Server::pump(){
	if (sock_fd < 0){
		return ServerPumpStatus::ERROR;
	}

	// first check for new clients, add them to pending clients and evict pending clients with same socket name
	while (true){
		std::string peer_addr;
		uint16_t peer_port;
		int accept_status = native_accept(sock_fd, &peer_addr, &peer_port);
		if (accept_status == -1){
			int err = native_get_last_socket_error();
			if (native_error_is_would_block(err)){
				break;
			}
			if (native_error_is_emfile(err)){
				LOG("%s: warning, new connection dropped as system limit has reached\n", __func__);
				break;
			}
			LOG("%s: accept call failed, 0x%x\n", __func__, err);
			return ServerPumpStatus::ERROR;
		}

		char socket_name_buf[128] = {0};
		sprintf(socket_name_buf, "%s:%u", peer_addr.c_str(), peer_port);
		std::string socket_name = std::string(socket_name_buf);
		Client new_client(accept_status, peer_addr, peer_port, socket_name, 1, &config);
		auto existing_pending_client = pending_clients.find(socket_name);
		if (existing_pending_client != pending_clients.end()){
			existing_pending_client->second.close_socket();
			pending_clients.erase(existing_pending_client);
		}
		pending_clients.insert_or_assign(socket_name, new_client);
	}

	if (pending_clients.size() == 0 && clients.size() == 0){
		return ServerPumpStatus::IDLE;
	}

	// process pending clients
	int worker_idx = 0;
	for (auto client = pending_clients.begin();client != pending_clients.end();client++){
		pending_client_work_queues[worker_idx].push_back(&client->second);
		worker_idx++;
		if (worker_idx == config.adhocctl_num_threads){
			worker_idx = 0;
		}
	}
	for (auto &start_sema : pending_clients_worker_start_sema){
		start_sema.release();
	}
	for (auto &finish_sema : pending_clients_worker_finish_sema){
		finish_sema.acquire();
	}

	for (auto &pending_remove_keys_per_thread : pending_clients_to_remove){
		for (auto &pending_remove_key : pending_remove_keys_per_thread){
			auto target = pending_clients.find(pending_remove_key);
			target->second.close_socket();
			pending_clients.erase(pending_remove_key);
		}
	}

	for (auto &pending_upgrade_keys_per_thread : pending_clients_to_upgrade){
		for (auto &pending_upgrade_key : pending_upgrade_keys_per_thread){
			auto target = pending_clients.find(pending_upgrade_key);

			std::string mac = target->second.get_mac();
			auto existing_client = clients.find(mac);
			if (existing_client != clients.end()){
				LOG("%s: session with mac address %s owned by %s now owned by %s\n", __func__, mac_bytes_to_mac_string(mac).c_str(), existing_client->second.get_socket_name().c_str(), target->second.get_socket_name().c_str());
				remove_client(target->second.get_mac());
			}

			if (config.adhocctl_relay_only){
				static uint32_t new_id = 0;
				while (true){
					bool is_unique = true;
					for (auto client = clients.begin();client != clients.end();client++){
						if (new_id == client->second.id){
							is_unique = false;
							new_id++;
							break;
						}
					}
					if (is_unique){
						break;
					}
				}
				target->second.id = new_id;
			} else {
				target->second.id = native_parse_ipv4(target->second.get_ip());
				if (target->second.id == 0xffffffff){
					LOG("%s: cannot parse ipv4 %s, debug this\n", __func__, target->second.get_ip().c_str());
					exit(1);
				}
			}

			clients.insert_or_assign(mac, target->second);
			connect_client(mac, "", true);

			pending_clients.erase(target);
		}
	}

	// pump data from clients
	int num_clients[config.adhocctl_num_threads] = {0};
	for (auto game = games.begin();game != games.end();game++){
		for (auto group = game->second.groups.begin();group != game->second.groups.end();group++){
			int least_used_worker = 0;
			for (int i = 0;i < config.adhocctl_num_threads;i++){
				if (num_clients[least_used_worker] > num_clients[i]){
					least_used_worker = i;
				}
			}

			client_recv_work_queue[least_used_worker].push_back(&group->second);
			num_clients[least_used_worker] += group->second.members.size();
		}
	}

	for (auto &start_sema : clients_recv_worker_start_sema){
		start_sema.release();
	}
	for (auto &finish_sema : clients_recv_worker_finish_sema){
		finish_sema.acquire();
	}

	// process group changing ops
	for (auto &op_collection : client_connect_disconnect_ops) {
		for (auto &op : op_collection){
			switch (op.op) {
				case ClientOp::CONNECT:
					connect_client(op.mac, op.connect.group, false);
					break;
				case ClientOp::DISCONNECT:
					connect_client(op.mac, "", true);
					break;
				default:
					LOG("%s: unreachable code path, debug this\n", __func__);
					exit(1);
			}
		}
	}

	// pump data to clients
	worker_idx = 0;
	for (auto client = clients.begin();client != clients.end();client++){
		client_send_work_queue[worker_idx].push_back(&client->second);
		worker_idx++;
		if (worker_idx == config.adhocctl_num_threads){
			worker_idx = 0;
		}
	}
	for (auto &start_sema : clients_send_worker_start_sema){
		start_sema.release();
	}
	for (auto &finish_sema : clients_send_worker_finish_sema){
		finish_sema.acquire();
	}

	// remove dead clients
	for (auto &clients_to_remove_per_thread : clients_to_remove){
		for (auto &mac : clients_to_remove_per_thread){
			remove_client(mac);
		}
	}

	// clear workqueues
	for (int i = 0;i < config.adhocctl_num_threads;i++){
		pending_client_work_queues[i].clear();
		pending_clients_to_remove[i].clear();
		pending_clients_to_upgrade[i].clear();

		client_recv_work_queue[i].clear();
		clients_to_remove[i].clear();
		client_connect_disconnect_ops[i].clear();
		client_send_work_queue[i].clear();
	}

	return ServerPumpStatus::SUCCESS;
}

}
