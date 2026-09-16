#pragma once

// enet is... oddly shaped, and there's not a lot of guide line to use it not in it's event thread shape

// let's wrap it so that:
// we pump it on a background thread
// we queue events in a c++ way
// we make it so each peer behaves more like sockets

#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <string>

#include <stdint.h>

namespace aemu_postoffice_enet_server {

enum class EnetAcceptStatus{
	SUCCESS,
	NO_PEER,
	ERROR,
};

enum class EnetRecvStatus{
	SUCCESS,
	WOULD_BLOCK,
	BUFFER_TOO_SMALL,
	PEER_CLOSED,
};

enum class EnetSendStatus{
	SUCCESS,
	PEER_CLOSED,
};

struct send_op {
	int peer_ref;
	std::string data;
	bool reliable;
	int channel;
};

struct recv_data {
	std::string data;
};

class BasicEnetServer{
	public:
		BasicEnetServer(std::string host, int port, int channels);
		int accept(std::string &peer_addr, int &peer_port, EnetAcceptStatus &status); // returns a peer ref, or -1 on error
		int recv(int peer_ref, char *buf, int buf_len, int channel, EnetRecvStatus &status); // returns buffer used, -1 on error
		int send(int peer_ref, const char *buf, int buf_len, int channel, bool reliable, EnetSendStatus &status); // returns data queued for sending, or -1 on error
		void close(int peer_ref);
	private:
		std::thread *worker;

		void *server; // let's not cause enet.h to be loaded everywhere, a ENetHost pointer, only enet_host_service loop should be touching this

		std::unordered_set<void *> new_peers; // peers to be used by accept(), a set of ENetPeer
		std::unordered_map<int, void *> peers; // peer ref to ENetPeer pointer, is null when a peer is disconnected
		std::unordered_map<void *, int> peers_lookup; // reverse lookup, mostly used during disconnect

		std::list<struct send_op> send_buffer;
		std::unordered_map<int, std::unordered_map<int, std::list<recv_data>>> recv_buffer; // peer ref -> channel -> list of recv_data

		std::mutex peer_mutex; // enet_host_server loop locks for new peers adding and disconnect handling, accept locks for upgrading new peers to peer, send/recv locks for quick checks
		std::mutex send_buffer_mutex; // send calls locks for writing, enet_peer_send calls locks for copying
		std::mutex recv_buffer_mutex; // recv calls locks for reading, enet_host_service loop locks for writing
};

}
