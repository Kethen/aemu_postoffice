#pragma once

// enet is... oddly shaped, and there's not a lot of guide line to use it not in it's event thread shape

// let's wrap it so that:
// we pump it on a background thread
// we queue events in a c++ way
// we make it so each peer behaves more like sockets

#include <mutex>
#include <shared_mutex>
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

struct peer {
	bool disconnected;
	void *peer; // a ENetPeer pointer
	std::mutex send_buf_mutex; // send locks for adding send operations, enet_host_service loop locks for draining send operations
	std::list<send_op> send_buf;
	std::mutex recv_buf_mutex; // recv locks for draining packet, enet_host_service loop locks for adding data
	std::unordered_map<int, std::list<recv_data>> recv_buf;
};

class BasicEnetServer{
	public:
		BasicEnetServer(std::string host, int port, int channels);
		int accept(std::string &peer_addr, int &peer_port, EnetAcceptStatus &status); // returns a peer ref, or -1 on error
		int recv(int peer_ref, char *buf, int buf_len, int channel, EnetRecvStatus &status); // returns buffer used, -1 on error
		int get_outgoing_data(int peer_ref); // returns data queued on enet for sending, returns -1 on a disconnected peer
		int send(int peer_ref, const char *buf, int buf_len, int channel, bool reliable, EnetSendStatus &status); // returns data queued for sending, or -1 on error
		int get_incoming_data(int peer_ref); // returns data queued on enet for receiving, returns -1 on a disconnected peer
		void close(int peer_ref);

	private:
		std::thread *worker;

		void *server; // let's not cause enet.h to be loaded everywhere, a ENetHost pointer, only enet_host_service loop should be touching this

		std::unordered_set<void *> new_peers; // peers to be used by accept(), a set of ENetPeer
		std::unordered_map<int, struct peer> peers;
		std::unordered_map<void *, int> peers_lookup; // reverse lookup, mostly used during disconnect

		std::list<struct send_op> send_buffer;
		std::unordered_map<int, std::unordered_map<int, std::list<recv_data>>> recv_buffer; // peer ref -> channel -> list of recv_data

		std::shared_mutex peer_mutex; // enet_host_service loop locks for new peers adding and disconnecting handling, enet_host_service share locks for recv/send handling, accept locks for upgrading new peers to peers, send/recv share locks for peer operations, close locks for removing peer
};

}
