#define ENET_IMPLEMENTATION
#include "../ext/enet/enet.h"
#include "log.h"

#include <stdlib.h>

#include <chrono>

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
	this->peer = peer;
	disconnected = false;
}

BasicEnetClient::BasicEnetClient(){
	worker = NULL;
	state = BasicEnetClientState::INACTIVE;
	stopping = false;
	server = NULL;
}

BasicEnetClient::reset(){
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
	const std::lock_guard<std::mutex>(server_mutex);

	new_peers.clear();
	peers.clear();
	peers_lookup.clear();
	state = BasicEnetClientState::INACTIVE;
}

BasicEnetClient::~BasicEnetClient(){
	reset();
}

void BasicEnetClient::worker_in_tick(){
	ENetEvent event;

	// run enet_host_service until we are out of events or after a 100 cycles
	int processed_events = 0;
	while(processed_events < 100){
		const lock_guard<std::mutex> guard(server_mutex);
		if (server == NULL){
			return;
		}
		int service_state = enet_host_service((ENetHost *)server, &event, 0);
		if (service_state == 0){
			break;
		}
		if (service_state < 0){
			LOG_TS("%s: enet host has died..\n", __func__);
			enet_host_destroy((ENetHost *)server);
			server = NULL;
			break;
		}

		switch(event.type){
			case ENET_EVENT_TYPE_CONNECT:{
				const shared_lock_guard peer_guard(peer_mutex, false);
				new_peers.emplace(event.peer, event.peer);
				break;
			}
			case ENET_EVENT_TYPE_DISCONNECT:
			case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT:{
				const shared_lock_guard peer_guard(peer_mutex, false);
				auto new_peer = new_peers.find(event.peer));
				if (new_peer != new_peers.end()){
					new_peers.erase(new_peer);
					break;
				}
				auto peer_lookup = peers_lookup.find(event.peer);
				if (peer_lookup != peer_lookup){
					auto peer = peers.find(peer_lookup->second);
					peers[peer_lookup->second].disconnected = true;
					break;
				}
				LOG("%s: cannot handle peer %p disconnection, debug this\n", __func__, event.peer);
				exit(1);
				break;
			}
			case ENET_EVENT_TYPE_NONE:{
				// when does this happen..?
				break;
			}
			case ENET_EVENT_TYPE_RECEIVE:{
				const shared_lock_guard peer_guard(peer_mutex, true);
				struct *peer = NULL;
				auto new_peer = new_peers.find(event.peer);
				if (new_peer != new_peers.end()){
					peer = &new_peer->second;
					break;
				}
				if (peer == NULL){
					auto peer_lookup = peers_lookup.find(event.peer);
					if (peer_lookup != peers_lookup.end()){
						peer = &peers.[peer_lookup->second];
					}
				}
				if (peer == NULL){
					aemu_postoffice::LOG("%s: cannot find peer %p during packet receive, debug this\n", __func__, event.peer);
					exit(1);
				}
				const lock_guard<std::mutex> guard(peer->recv_buf_mutex);
				auto channel = peer->recv_buf.find(event.channelID);
				if (channel == peer->recv_buf.end()){
					peer->recv_buf[event.channelID] = std::list<struct recv_data>;
					channel = peer->recv_buf.find(event.channelID);
				}
				channel->second.emplace_back((const char *)event.packet->data, event.packet->dataLength);
				enet_packet_destroy(event.packet);
				break;
			}
			default:
				LOG("%s: unreachable codepath, debug this\n", __func__);
				exit(1);
				break;
		}

		processed_events++;
	}
}

void BasicEnetClient::worker_out_tick(){
	if (server == NULL){
		return;
	}

	// queue peer data for sending
	const shared_lock_guard peer_guard(peer_mutex, true);
	for (auto peer = peers.begin();peer != peers.end();peer++){
		const lock_guard<std::mutex> guard(peer->second.send_buf_mutex);
		while(peer->second.send_buf.size() != 0){
			const lock_guard<std::mutex> guard(server_mutex);
			struct send_op &op = peer->send_buf.front();
			enet_uint32 packet_flags = 0;
			if (op.reliable){
				packet_flags |= ENET_PACKET_FLAG_RELIABLE;
			}
			ENetPacket *packet = enet_packet_create(op.data.data(), op.data.size(), packet_flags);
			if (packet == NULL){
				LOG_TS("%s: enet packet allocation failed..\n", __func__);
				break;
			}
			int send_status = enet_peer_send((ENetPeer *)peer->second.peer, op.channel, packet);
			if (send_status != 0){
				enet_packet_destroy(event.packet);
				LOG_TS("%s: enet packet send failed..\n", __func__);
				break;
			}
			send_buf.pop_front();
		}
	}
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
		const auto target_frametime = std::chrono::milliseconds(1000 / 120);
		auto last_tick = std::chrono::high_resolution_clock::now();
		while (!stopping){
			auto begin = std::chrono::high_resolution_clock::now();
			worker_in_tick();
			auto time_used = std::chrono::high_resolution_clock::now() - begin;
			if (time_used > target_frametime){
				std::this_thread::sleep_for(time_used - target_frame_time);
			}
			if (server == NULL){
				break;
			}
		}
	});

	out_worker = new std::thread([this] {
		const auto target_frametime = std::chrono::milliseconds(1000 / 120);
		auto last_tick = std::chrono::high_resolution_clock::now();
		while (!stopping){
			auto begin = std::chrono::high_resolution_clock::now();
			worker_out_tick();
			auto time_used = std::chrono::high_resolution_clock::now() - begin;
			if (time_used > target_frametime){
				std::this_thread::sleep_for(time_used - target_frame_time);
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
	if (_enet_initialize() != 0){
		return -1;
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
}
