#include "enet.h"
#include "mutex_impl.h"
#include "log.h"

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define ENET_IMPLEMENTATION
#ifdef __PSP__
// TODO psp networking shims
#define ENET_IPV4_ONLY
#endif
#include "../ext/enet/enet.h"

struct channel{
	int channel;
	void *packet_list; // list of ENetPacket *
};

struct connection{
	ENetHost *host;
	ENetPeer *peer;
	void *incoming_packets; // list of struct channel
	bool closed; // closed on this api with disconnect queued into enet
	bool disconnected; // disconnected on enet
};

static void *connections = NULL; // list of struct connection *

static int _init_enet(){
	if (connections != NULL){
		return 0;
	}
	connections = init_list();
	if (connections == NULL){
		LOG("%s: failed allocating connection list for enet\n", __func__);
		return -1;
	}
}

int init_enet(){
	lock_enet_mutex();
	int ret = _init_enet();
	unlock_enet_mutex();
	return ret;
}

static void _deinit_enet(){
	if (connections == NULL){
		return;
	}

	void *itr = list_begin_itr(connections);
	while(itr != NULL){
		struct connection *connection = (struct connection *connection)list_itr_get_data(itr);

		void *channel_itr = list_begin_itr(connection->incoming_packets);
		while(channel_itr != NULL){
			struct channel *channel = list_itr_get_data(channel_itr);
			void *packet_itr = list_begin_itr(channel->packet_list);
			while(packet_itr != NULL){
				ENetPacket *packet = (ENetPacket *)list_itr_get_data(packet_itr);
				enet_packet_destroy(packet);
				packet_itr = list_itr_next(packet_itr);
			}
			free_list(channel->packet_list);
			channel_itr = list_itr_next(channel_itr);
		}
		free_list(connection->incoming_packets);

		enet_host_destroy(connection->host);

		itr = list_itr_next(itr);
	}

	free_list(connections);
	connections = NULL;
}

void deinit_enet(){
	lock_enet_mutex();
	_deinit_enet();
	unlock_enet_mutex();
}

// there is only little endian now
static uint32_t _ntohl(uint32_t net){
	uint32_t host = 0;
	uint8_t *host_bytes = (uint8_t *)&host;
	uint8_t *net_bytes = (uint8_t *)&net;
	host_bytes[0] = net_bytes[3];
	host_bytes[1] = net_bytes[2];
	host_bytes[2] = net_bytes[1];
	host_bytes[3] = net_bytes[0];
	return host;
}

static uint32_t _htonl(uint32_t host){
	return _ntohl(host);
}

static uint16_t _ntohs(uint16_t net){
	uint16_t host = 0;
	uint8_t *host_bytes = (uint8_t *)&host;
	uint8_t *net_bytes = (uint8_t *)&net;
	host_bytes[0] = net_bytes[1];
	host_bytes[1] = net_bytes[0];
	return host;
}

static uint16_t _htons(uint16_t host){
	return _ntohs(host);
}

static void *_connect_enet(const ENetAddress *addr, channels){
	ENetHost *client = enet_host_create(NULL, 1, channels, 0, 0);

	if (client == NULL){
		return NULL;
	}

	ENetPeer *server = enet_host_connect(client, addr, channels, 0);
	if (peer == NULL){
		enet_host_destroy(client);
		return NULL;
	}

	struct connection *new_connection = (struct connection *)malloc(sizeof(new_connection));
	if (new_connection == NULL){
		LOG("%s: failed allocating new connection\n", __func__);
		enet_host_destroy(client);
		return NULL;
	}

	new_connection->incoming_packets = init_list();
	if (new_connection->incoming_packets){
		LOG("%s: failed allocating incoming packets list\n", __func__);
		enet_host_destroy(client);
		free(new_connection);
		return NULL;
	}

	new_connection->host = client;
	new_connection->peer = server;
	new_connection->closed = false;
	new_connection->disconnected = false;

	bool push_status = list_push_back(connections, new_connection);
	if (!push_status){
		LOG("%s: failed adding new connection to connection list\n", __func__);
		enet_host_destroy(client);
		free_list(new_connection->incoming_packets);
		free(new_connection);
		return NULL;
	}
	return new_connection;
}

static void *connect_enet(const ENetAddress *addr, channels){
	lock_enet_mutex();
	void *ret = _connect_enet(addr, channels);
	unlock_enet_mutex();
	return ret;
};

void *connect_v4_enet(const struct aemu_post_office_sock_addr *addr, int channels){
	ENetAddress enet_addr = {0};

	#ifdef __PSP__
	// just v4
	enet_addr.host.s_addr = addr->addr;
	#else
	// v4 in v6
	uint8_t *v6_bytes = (uint8_t *)enet_addr.host.s6_addr;
	uint8_t *v4_bytes = (uint8_t *)&addr->addr;
	v6_bytes[10] = 0xff;
	v6_bytes[11] = 0xff;
	v6_bytes[12] = v4_bytes[0];
	v6_bytes[13] = v4_bytes[1];
	v6_bytes[14] = v4_bytes[2];
	v6_bytes[15] = v4_bytes[3];
	#endif
	enet_addr.port = _ntohs(addr->port);

	return connect_enet(&enet_addr, channels);
}

void *connect_v6_enet(const struct aemu_post_office_sock_addr *addr, int channels){
	#ifdef __PSP__
	// no v6 support
	return NULL;
	#endif

	ENetAddress enet_addr = {0};
	memcpy(enet_addr.host.s6_addr, addr->addr, 16);
	enet_addr.port = _ntohs(addr->port);

	return connect_enet(&enet_addr, channels);
}
