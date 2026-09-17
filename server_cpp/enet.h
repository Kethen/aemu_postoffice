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
#include <list>
#include <string>

namespace aemu_postoffice_enet {

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
	std::string data;
	bool reliable;
	int channel;
};

struct peer {
	bool disconnected;
	void *peer; // a ENetPeer pointer
	std::mutex send_buf_mutex; // send locks for adding send operations, enet_host_service loop locks for draining send operations
	std::list<send_op> send_buf;
	std::mutex recv_buf_mutex; // recv locks for draining packet, enet_host_service loop locks for adding data
	std::unordered_map<int, std::list<std::string>> recv_buf;

	peer(void *peer);
};

enum class BasicEnetClientState{
	INACTIVE,
	LISTEN,
	CONNECT,
};

class BasicEnetClient{
	public:
		BasicEnetClient();
		~BasicEnetClient();
		int listen(const std::string &host, int port, int max_peers, int channels); // returns 0 on success, -1 on error
		int accept(std::string &peer_addr, int &peer_port, EnetAcceptStatus &status); // returns a peer ref, or -1 on error, only usable in listen mode
		int connect(const std::string &host, int port); // returns a peer ref, or -1 on error
		int recv(int peer_ref, char *buf, int buf_len, int channel, EnetRecvStatus &status); // returns buffer used, -1 on error
		int get_outgoing_data(int peer_ref); // returns data queued on enet for sending, returns -1 on a disconnected peer
		int send(int peer_ref, const char *buf, int buf_len, int channel, bool reliable, EnetSendStatus &status); // returns data queued for sending, or -1 on error
		int get_incoming_data(int peer_ref); // returns data queued on enet for receiving, returns -1 on a disconnected peer
		void close(int peer_ref);
		int reset();

	private:
		bool stopping;
		std::thread *in_worker;
		std::thread *out_worker;
		BasicEnetClientState state;

		std::mutex server_mutex;
		void *server; // let's not cause enet.h to be loaded everywhere, a ENetHost pointer, only enet_host_service loop should be touching this

		std::unordered_map<void *, struct peer> new_peers; // peers to be used by accept(), a set of ENetPeer
		std::unordered_map<int, struct peer> peers;
		std::unordered_map<void *, int> peers_lookup; // reverse lookup, for handling events on enet_host_service loop

		std::shared_mutex peer_mutex; // enet_host_service loop locks for new peers adding and disconnecting handling, enet_host_service share locks for recv/send handling, accept locks for upgrading new peers to peers, send/recv share locks for peer operations, close locks for removing peer

		void worker_in_tick();
		void worker_out_tick();
		void create_workers();
};

}
