#define ENET_IMPLEMENTATION
#include "../ext/enet/enet.h"
#include "log.h"
#include "common.h"

#include <stdlib.h>
#include <limits.h>

#include <chrono>

#include "enet.h"

using namespace aemu_postoffice_server;

namespace aemu_postoffice_enet {

class shared_lock_guard{
	public:
		shared_lock_guard(std::shared_mutex &lock, bool shared){
			this->lock = &lock;
			this->shared = shared;
			if (shared)
				lock.lock_shared();
			else
				lock.lock();
		}
		~shared_lock_guard(){
			if (shared)
				lock->unlock_shared();
			else
				lock->unlock();
		}
	private:
		std::shared_mutex *lock;
		bool shared;
};

peer::peer(void *peer){
	this->enet_peer = peer;
	disconnected = false;
	closed = false;
}

peer::peer(peer &copy){
	enet_peer = copy.enet_peer;
	send_buf = copy.send_buf;
	recv_buf = copy.recv_buf;
	disconnected = copy.disconnected;
	closed = copy.closed;
}

BasicEnetClient::BasicEnetClient(){
	in_worker = NULL;
	out_worker = NULL;
	state = BasicEnetClientState::INACTIVE;
	stopping = false;
	server = NULL;
}

void BasicEnetClient::reset(){
	stopping = true;
	if (in_worker != NULL){
		in_worker->join();
		delete in_worker;
		in_worker = NULL;
	}
	if (out_worker != NULL){
		out_worker->join();
		delete out_worker;
		out_worker = NULL;
	}
	if (server != NULL){
		enet_host_destroy((ENetHost *)server);
		server = NULL;
	}
	const shared_lock_guard peer_guard(peer_mutex, false);
	const std::lock_guard<std::mutex> guard(server_mutex);

	new_peers.clear();
	new_peers_ordered.clear();
	peers.clear();
	peers_lookup.clear();
	state = BasicEnetClientState::INACTIVE;
}

BasicEnetClient::~BasicEnetClient(){
	reset();
}

WorkerTickStatus BasicEnetClient::worker_in_tick(){
	ENetEvent event;

	const std::lock_guard<std::mutex> guard(server_mutex);
	if (server == NULL){
		return WorkerTickStatus::ERRORED;
	}
	int service_state = enet_host_service((ENetHost *)server, &event, 0);

	if (service_state < 0){
		LOG_TS("%s: enet host has died..\n", __func__);
		enet_host_destroy((ENetHost *)server);
		server = NULL;
		return WorkerTickStatus::ERRORED;
	}

	if (service_state == 0){
		return WorkerTickStatus::IDLE;
	}

	if (new_peers.size() == 0 && peers.size()){
		return WorkerTickStatus::IDLE;
	}

	switch(event.type){
		case ENET_EVENT_TYPE_CONNECT:{
			const shared_lock_guard peer_guard(peer_mutex, false);
			if (state == BasicEnetClientState::CONNECT){
				// in connect mode we already have a peer
				return WorkerTickStatus::SUCCESS;
			}
			if (peers_lookup.find(event.peer) != peers_lookup.end() || new_peers.find(event.peer) != new_peers.end()){
				LOG("%s: unexpected second connect event from peer %p, debug this\n", __func__, event.peer);
				exit(1);
			}
			create_peer_reference(event.peer);
			return WorkerTickStatus::SUCCESS;
		}
		case ENET_EVENT_TYPE_DISCONNECT:
		case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT:{
			const shared_lock_guard peer_guard(peer_mutex, false);
			auto new_peer = new_peers.find(event.peer);
			if (new_peer != new_peers.end()){
				new_peers.erase(new_peer);
				for(auto ordered_new_peer = new_peers_ordered.begin();ordered_new_peer != new_peers_ordered.end();ordered_new_peer++){
					if (*ordered_new_peer == event.peer){
						new_peers_ordered.erase(ordered_new_peer);
						break;
					}
				}
				return WorkerTickStatus::SUCCESS;
			}
			auto peer_lookup = peers_lookup.find(event.peer);
			if (peer_lookup != peers_lookup.end()){
				auto peer = peers.find(peer_lookup->second);
				if (!peer->second.closed){
					peer->second.disconnected = true;
					return WorkerTickStatus::SUCCESS;
				}

				auto peer_lookup = peers_lookup.find(peer->second.enet_peer);
				peers_lookup.erase(peer_lookup);
				peers.erase(peer);
				return WorkerTickStatus::SUCCESS;
			}
			LOG("%s: cannot handle peer %p disconnection, debug this\n", __func__, event.peer);
			exit(1);
			return WorkerTickStatus::ERRORED;
		}
		case ENET_EVENT_TYPE_NONE:{
			// when does this happen..?
			return WorkerTickStatus::SUCCESS;
		}
		case ENET_EVENT_TYPE_RECEIVE:{
			const shared_lock_guard peer_guard(peer_mutex, true);
			struct peer *peer = NULL;
			auto new_peer = new_peers.find(event.peer);
			if (new_peer != new_peers.end()){
				peer = &new_peer->second;
			}
			if (peer == NULL){
				auto peer_lookup = peers_lookup.find(event.peer);
				if (peer_lookup != peers_lookup.end()){
					peer = &peers.find(peer_lookup->second)->second;
				}
			}
			if (peer == NULL){
				LOG("%s: cannot find peer %p during packet receive, debug this\n", __func__, event.peer);
				exit(1);
				return WorkerTickStatus::ERRORED;
			}
			const std::lock_guard<std::mutex> guard(peer->recv_buf_mutex);
			auto channel = peer->recv_buf.find(event.channelID);
			if (channel == peer->recv_buf.end()){
				peer->recv_buf[event.channelID] = std::list<std::string>();
				channel = peer->recv_buf.find(event.channelID);
			}
			channel->second.emplace_back((const char *)event.packet->data, event.packet->dataLength);
			enet_packet_destroy(event.packet);
			return WorkerTickStatus::SUCCESS;
		}
		default:
			LOG("%s: unreachable codepath with event type %d, debug this\n", __func__, event.type);
			exit(1);
			return WorkerTickStatus::ERRORED;
	}
}

WorkerTickStatus BasicEnetClient::worker_out_tick(){
	if (server == NULL){
		return WorkerTickStatus::ERRORED;
	}

	// queue peer data for sending
	const shared_lock_guard peer_guard(peer_mutex, true);
	if (peers.size() == 0){
		return WorkerTickStatus::IDLE;
	}
	bool idle = true;
	for (auto peer = peers.begin();peer != peers.end();peer++){
		const std::lock_guard<std::mutex> guard(peer->second.send_buf_mutex);
		if (peer->second.disconnected){
			continue;
		}
		while(peer->second.send_buf.size() != 0){
			idle = false;
			const std::lock_guard<std::mutex> guard(server_mutex);
			struct send_op &op = peer->second.send_buf.front();
			enet_uint32 packet_flags = 0;
			if (op.reliable){
				packet_flags |= ENET_PACKET_FLAG_RELIABLE;
			}
			ENetPacket *packet = enet_packet_create(op.data.data(), op.data.size(), packet_flags);
			if (packet == NULL){
				LOG_TS("%s: enet packet allocation failed..\n", __func__);
				break;
			}
			int send_status = enet_peer_send((ENetPeer *)peer->second.enet_peer, op.channel, packet);
			if (send_status != 0){
				enet_packet_destroy(packet);
				LOG_TS("%s: enet packet send failed..\n", __func__);
				break;
			}
			peer->second.send_buf.pop_front();
		}
	}

	return idle ? WorkerTickStatus::IDLE : WorkerTickStatus::SUCCESS;
}

static int _enet_initialize(){
	static bool initialized = false;
	static std::mutex init_mutex;
	const std::lock_guard<std::mutex> guard(init_mutex);
	if (initialized){
		return 0;
	}

	int initialize_result = enet_initialize();
	if (initialize_result == 0){
		initialized = true;
		return 0;
	}
	LOG("%s: failed initializing enet, 0x%x\n", __func__, initialize_result);
	return initialize_result;
}

bool BasicEnetClient::create_workers(){
	stopping = false;
	in_worker = new std::thread([this] {
		set_thread_name("enet in");
		const auto target_frametime = std::chrono::milliseconds(1000 / 120);
		while (!stopping){
			auto begin = std::chrono::high_resolution_clock::now();
			WorkerTickStatus tick_status = worker_in_tick();
			auto time_used = std::chrono::high_resolution_clock::now() - begin;
			if (time_used < target_frametime && tick_status == WorkerTickStatus::IDLE){
				std::this_thread::sleep_for(target_frametime - time_used);
			}
			if (server == NULL){
				break;
			}
		}
	});

	out_worker = new std::thread([this] {
		set_thread_name("enet out");
		const auto target_frametime = std::chrono::milliseconds(1000 / 120);
		const auto target_frametime_idle = std::chrono::milliseconds(1000 / 30);
		while (!stopping){
			auto begin = std::chrono::high_resolution_clock::now();
			WorkerTickStatus tick_status = worker_out_tick();
			auto time_used = std::chrono::high_resolution_clock::now() - begin;
			const auto &final_frametime_target = tick_status == WorkerTickStatus::IDLE ? target_frametime_idle : target_frametime;
			if (time_used < final_frametime_target){
				std::this_thread::sleep_for(final_frametime_target - time_used);
			}
			if (server == NULL){
				break;
			}
		}
	});

	if (in_worker == NULL || out_worker == NULL){
		return false;
	}
	return true;
}

int BasicEnetClient::listen(const std::string &host, int port, int max_peers, int channels){
	const std::lock_guard<std::mutex> guard(server_mutex);
	if (_enet_initialize() != 0){
		return -1;
	}

	if (state != BasicEnetClientState::INACTIVE){
		LOG("%s: enet client is not inactive, debug this\n", __func__);
		exit(1);
	}

	ENetAddress enet_addr = {0};
	enet_address_set_host_ip(&enet_addr, host.c_str());
	enet_addr.port = port;
	server = enet_host_create(&enet_addr, max_peers, channels, 0, 0);

	if (server == NULL){
		reset();
		return -1;
	}

	if (!create_workers()){
		reset();
		return -1;
	}

	state = BasicEnetClientState::LISTEN;
	return 0;
}

int BasicEnetClient::accept(std::string &peer_addr, int &peer_port, EnetAcceptStatus &status){
	const shared_lock_guard peer_guard(peer_mutex, false);
	if (new_peers.size() == 0){
		status = EnetAcceptStatus::NO_PEER;
		return -1;
	}

	ENetPeer *peer = (ENetPeer *)new_peers_ordered.front();
	char addr_buf[256] = {0};
	int translate_status = enet_address_get_host_ip(&peer->address, addr_buf, sizeof(addr_buf));
	if (translate_status != 0){
		LOG("%s: enet failed to translate peer address back to string, wtf\n", __func__);
		exit(1);
		status = EnetAcceptStatus::ERROR;
		return -1;
	}
	addr_buf[sizeof(addr_buf) - 1] = '\0';
	peer_addr = std::string(addr_buf);
	peer_port = peer->address.port;

	int peer_ref = upgrade_peer(peer);
	if (peer_ref == -1){
		status = EnetAcceptStatus::NO_PEER;
		return -1;
	}

	status = EnetAcceptStatus::SUCCESS;
	return peer_ref;
}

// assumes peer lock
void BasicEnetClient::create_peer_reference(void *peer){
	new_peers.emplace(peer, peer);
	new_peers_ordered.push_back(peer);
}

// assumes peer lock
int BasicEnetClient::upgrade_peer(void *peer){
	static int ref = 1;

	if (peers.size() >= INT_MAX - 1){
		return -1;
	}

	while(peers.find(ref) != peers.end()){
		ref++;
		if (ref < 0){
			ref = 1;
		}
	}

	auto new_peer = new_peers.find(peer);
	if (new_peer == new_peers.end()){
		LOG("%s: trying to upgrade non existing peer, debug this\n", __func__);
		exit(1);
	}
	peers.emplace(ref, new_peer->second);
	peers_lookup[peer] = ref;
	new_peers.erase(new_peer);

	for(auto ordered_new_peer = new_peers_ordered.begin();ordered_new_peer != new_peers_ordered.end();ordered_new_peer++){
		if (*ordered_new_peer == peer){
			new_peers_ordered.erase(ordered_new_peer);
			break;
		}
	}

	return ref;
}

int BasicEnetClient::connect(const std::string &host, int port, int channels){
	const std::lock_guard<std::mutex> guard(server_mutex);
	if (_enet_initialize() != 0){
		return -1;
	}

	if (state != BasicEnetClientState::INACTIVE){
		LOG("%s: enet client is not inactive, debug this\n", __func__);
		exit(1);
	}

	ENetAddress enet_addr = {0};
	enet_address_set_host_ip(&enet_addr, host.c_str());
	enet_addr.port = port;
	server = enet_host_create(NULL, 1, channels, 0, 0);

	if (server == NULL){
		reset();
		return -1;
	}

	ENetPeer *peer = enet_host_connect((ENetHost *)server, &enet_addr, channels, 0);
	if (peer == NULL){
		reset();
		return -1;
	}

	if (!create_workers()){
		reset();
		return -1;
	}

	const shared_lock_guard peer_guard(peer_mutex, false);
	create_peer_reference(peer);
	int peer_ref = upgrade_peer(peer);

	state = BasicEnetClientState::CONNECT;

	return peer_ref;
}

int BasicEnetClient::recv(int peer_ref, char *buf, int buf_len, int channel, EnetRecvStatus &status){
	const shared_lock_guard peer_guard(peer_mutex, true);
	auto peer = peers.find(peer_ref);
	if (peer == peers.end() || peer->second.closed){
		status = EnetRecvStatus::PEER_NOT_FOUND;
		return -1;
	}

	if (peer->second.disconnected){
		status = EnetRecvStatus::PEER_CLOSED;
		return -1;
	}

	const std::lock_guard<std::mutex> guard(peer->second.recv_buf_mutex);
	auto channel_buf = peer->second.recv_buf.find(channel);
	if (channel_buf == peer->second.recv_buf.end()){
		status = EnetRecvStatus::WOULD_BLOCK;
		return -1;
	}

	if (channel_buf->second.size() == 0){
		status = EnetRecvStatus::WOULD_BLOCK;
		return -1;
	}

	const auto &packet = channel_buf->second.front();
	int packet_size = packet.size();
	if (packet_size > buf_len){
		status = EnetRecvStatus::BUFFER_TOO_SMALL;
		return -1;
	}

	memcpy(buf, packet.data(), packet_size);
	channel_buf->second.pop_front();
	status = EnetRecvStatus::SUCCESS;
	return packet_size;
}

send_op::send_op(const std::string &data, bool reliable, int channel){
	this->data = data;
	this->reliable = reliable;
	this->channel = channel;
}

int BasicEnetClient::send(int peer_ref, const char *buf, int buf_len, int channel, bool reliable, EnetSendStatus &status){
	const shared_lock_guard peer_guard(peer_mutex, true);
	auto peer = peers.find(peer_ref);
	if (peer == peers.end() || peer->second.closed){
		status = EnetSendStatus::PEER_NOT_FOUND;
		return -1;
	}

	if (peer->second.disconnected){
		status = EnetSendStatus::PEER_CLOSED;
		return -1;
	}

	const std::lock_guard<std::mutex> guard(peer->second.send_buf_mutex);
	peer->second.send_buf.emplace_back(std::string(buf, buf_len), reliable, channel);
	status = EnetSendStatus::SUCCESS;
	return buf_len;
}

int BasicEnetClient::get_incoming_data(int peer_ref, int channel){
	const shared_lock_guard peer_guard(peer_mutex, true);
	auto peer = peers.find(peer_ref);
	if (peer == peers.end()){
		return -1;
	}
	if (peer->second.disconnected || peer->second.closed){
		return -1;
	}

	const std::lock_guard<std::mutex> guard(peer->second.recv_buf_mutex);
	auto channel_buf = peer->second.recv_buf.find(channel);
	if (channel_buf == peer->second.recv_buf.end()){
		return 0;
	}
	int size = 0;
	for (const auto &packet : channel_buf->second){
		size += packet.size();
	}
	return size;
}

int BasicEnetClient::get_outgoing_data(int peer_ref, int channel){
	const shared_lock_guard peer_guard(peer_mutex, true);
	auto peer = peers.find(peer_ref);
	if (peer == peers.end()){
		return -1;
	}
	if (peer->second.disconnected || peer->second.closed){
		return -1;
	}

	const std::lock_guard<std::mutex> guard(peer->second.send_buf_mutex);
	int size = 0;
	for (const auto &send_op : peer->second.send_buf){
		if (send_op.channel != channel){
			continue;
		}
		size += send_op.data.size();
	}

	return size;
}

void BasicEnetClient::close(int peer_ref){
	// changing the lock order here could cause dead lock with worker_in_tick
	const std::lock_guard<std::mutex> guard(server_mutex);
	const shared_lock_guard peer_guard(peer_mutex, false);
	auto peer = peers.find(peer_ref);
	if (peer == peers.end()){
		LOG("%s: removing non existing peer %d\n", __func__, peer_ref);
		exit(1);
		return;
	}

	if (!peer->second.disconnected){
		peer->second.closed = true;
		enet_peer_disconnect((ENetPeer *)peer->second.enet_peer, 0);
		return;
	}

	auto peer_lookup = peers_lookup.find(peer->second.enet_peer);
	peers_lookup.erase(peer_lookup);
	peers.erase(peer);
}

}
