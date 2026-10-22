#include "enet.h"
#include "mutex_impl.h"
#include "log_impl.h"
#include "list.h"
#include "delay_impl.h"

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define ENET_IMPLEMENTATION

#ifdef __PSP__
// TODO psp networking shims
#include "psp_enet_shim.h"
#define ENET_IPV4_ONLY
#endif

#ifdef __APPLE__
// Older Apple clang (Xcode 16.0) doesn't predefine the TARGET_OS_* macros.
#include <TargetConditionals.h>
#endif

#if __APPLE__ && (TARGET_OS_SIMULATOR || TARGET_OS_IPHONE)
#define __MAC_OS_X_VERSION_MIN_REQUIRED 101200
#endif

#include "../ext/enet/enet.h"

#if __APPLE__ && (TARGET_OS_SIMULATOR || TARGET_OS_IPHONE)
#undef __MAC_OS_X_VERSION_MIN_REQUIRED
#endif

struct channel{
	int channel;
	void *packet_list; // list of ENetPacket *
	int packet_offset;
};

struct connection{
	ENetHost *host;
	ENetPeer *peer;
	void *incoming_packets; // list of struct channel
	bool closed; // closed on this api with disconnect queued into enet
	bool disconnected; // disconnected on enet
	bool connected;
};

static void *connections = NULL; // list of struct connection *

static int _enet_initialize(){
	static bool initialized = false;

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

static int _init_enet(){
	if (_enet_initialize() != 0){
		return -1;
	}

	if (connections != NULL){
		return 0;
	}
	connections = init_list();
	if (connections == NULL){
		LOG("%s: failed allocating connection list for enet\n", __func__);
		return -1;
	}
	return 0;
}

int init_enet(){
	lock_enet_mutex();
	int ret = _init_enet();
	unlock_enet_mutex();
	return ret;
}

static void free_connection(struct connection *connection){
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
		free(channel);
		channel_itr = list_itr_next(channel_itr);
	}
	free_list(connection->incoming_packets);

	enet_host_destroy(connection->host);
	free(connection);
}

static void _deinit_enet(){
	if (connections == NULL){
		return;
	}

	void *itr = list_begin_itr(connections);
	while (itr != NULL){
		struct connection *connection = (struct connection *)list_itr_get_data(itr);
		free_connection(connection);
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

static void *_connect_enet(const ENetAddress *addr, int channels){
	if (connections == NULL){
		LOG("%s: enet is not initialized\n", __func__);
		return NULL;
	}

	ENetHost *client = enet_host_create(NULL, 1, channels, 0, 0);

	if (client == NULL){
		return NULL;
	}

	ENetPeer *server = enet_host_connect(client, addr, channels, 0);
	if (server == NULL){
		enet_host_destroy(client);
		return NULL;
	}

	struct connection *new_connection = (struct connection *)malloc(sizeof(struct connection));
	if (new_connection == NULL){
		LOG("%s: failed allocating new connection\n", __func__);
		enet_host_destroy(client);
		return NULL;
	}

	new_connection->incoming_packets = init_list();
	if (new_connection->incoming_packets == NULL){
		LOG("%s: failed allocating incoming packets list\n", __func__);
		enet_host_destroy(client);
		free(new_connection);
		return NULL;
	}

	new_connection->host = client;
	new_connection->peer = server;
	new_connection->closed = false;
	new_connection->disconnected = false;
	new_connection->connected = false;

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

static bool is_connected(struct connection *connection){
	lock_enet_mutex();
	bool connected = connection->connected;
	unlock_enet_mutex();
	return connected;
}

static void *find_connection_itr(struct connection *connection){
	void *itr = list_begin_itr(connections);
	while(itr != NULL){
		if (list_itr_get_data(itr) == connection){
			break;
		}
		itr = list_itr_next(itr);
	}
	return itr;
}

// looking at enet.h, it seems that calling enet_peer_disconnect on not connected peer will just do a enet_peer_reset, and there will be no ENET_EVENT_TYPE_DISCONNECT nor ENET_EVENT_TYPE_DISCONNECT_TIMEOUT later
// this behavior is not documented anywhere, so I also can't take this as a contract to how future revision of enet would work
// enet_peer_disconnect_now however promises on documentation to perform a event-less best effort disconnect without waiting for remote acknowledgement
static void close_now_enet(struct connection *connection){
	lock_enet_mutex();
	void *itr = find_connection_itr(connection);
	enet_peer_disconnect_now(connection->peer, 0);
	free_connection(connection);
	list_remove(connections, itr);
	unlock_enet_mutex();
}

void *connect_enet(const struct aemu_postoffice_sock_addr *addr4, const struct aemu_postoffice_sock6_addr *addr6, int channels, bool (*abort_connection)(void *arg), void *abort_connection_arg){
	ENetAddress enet_addr = {0};
	if (addr4 != NULL){
		#ifdef __PSP__
		// just v4
		enet_addr.host.s_addr = addr4->addr;
		#else
		// v4 in v6
		uint8_t *v6_bytes = (uint8_t *)enet_addr.host.s6_addr;
		uint8_t *v4_bytes = (uint8_t *)&addr4->addr;
		v6_bytes[10] = 0xff;
		v6_bytes[11] = 0xff;
		v6_bytes[12] = v4_bytes[0];
		v6_bytes[13] = v4_bytes[1];
		v6_bytes[14] = v4_bytes[2];
		v6_bytes[15] = v4_bytes[3];
		#endif
		enet_addr.port = _ntohs(addr4->port);
	} else {
		#ifdef __PSP__

		// no v6 support
		return NULL;

		#else

		memcpy(enet_addr.host.s6_addr, addr6->addr, 16);
		enet_addr.port = _ntohs(addr6->port);

		#endif
	}

	lock_enet_mutex();
	struct connection *ret = (struct connection *)_connect_enet(&enet_addr, channels);
	unlock_enet_mutex();

	if (ret != NULL){
		int time_spent_ms = 0;
		while (true){
			if (is_connected(ret)){
				break;
			}
			if (time_spent_ms >= 5000 || (abort_connection != NULL && abort_connection(abort_connection_arg))){
				close_now_enet(ret);
				return NULL;
			}
			delay(100);
			time_spent_ms += 100;
		}
	}

	return ret;
};

static void _close_enet(void *handle){
	if (connections == NULL){
		LOG("%s: enet is not initialized\n", __func__);
		return;
	}

	struct connection *connection = (struct connection *)handle;

	void *itr = find_connection_itr(connection);

	if (itr == NULL){
		LOG("%s: unknown connection %p...\n", __func__, handle);
		return;
	}

	if (connection->disconnected){
		free_connection(connection);
		list_remove(connections, itr);
		return;
	}

	enet_peer_disconnect(connection->peer, 0);
	connection->closed = true;
	return;
}

void close_enet(void *handle){
	lock_enet_mutex();
	_close_enet(handle);
	unlock_enet_mutex();
}

static int _pump_enet(){
	if (connections == NULL){
		LOG("%s: enet is not initialized\n", __func__);
		return -1;
	}

	void *itr = list_begin_itr(connections);
	ENetEvent event;
	int events_processed = 0;
	while (itr != NULL){
		struct connection *connection = list_itr_get_data(itr);
		if (connection->disconnected){
			itr = list_itr_next(itr);
			continue;
		}
		int service_status = enet_host_service(connection->host, &event, 0);
		if (service_status == 0){
			itr = list_itr_next(itr);
			continue;
		}
		if (service_status < 0){
			LOG("%s: servicing of connection %p failed...\n", __func__, connection);
			connection->disconnected = true;
			itr = list_itr_next(itr);
			continue;
		}
		events_processed++;
		switch (event.type){
			case ENET_EVENT_TYPE_CONNECT:
				connection->connected = true;
				break;
			case ENET_EVENT_TYPE_DISCONNECT:
			case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT:{
				if (connection->closed){
					free_connection(connection);
					void *last_itr = itr;
					itr = list_itr_next(itr);
					list_remove(connections, last_itr);
					continue;
				}
				connection->disconnected = true;
				break;
			}
			case ENET_EVENT_TYPE_NONE:
				// now when does this happen..
				break;
			case ENET_EVENT_TYPE_RECEIVE:{
				void *channel_itr = list_begin_itr(connection->incoming_packets);
				while(channel_itr != NULL){
					struct channel *channel = list_itr_get_data(channel_itr);
					if (channel->channel == event.channelID){
						break;
					}
					channel_itr = list_itr_next(channel_itr);
				}
				if (channel_itr == NULL){
					struct channel *new_channel = (struct channel *)malloc(sizeof(struct channel));
					if (new_channel == NULL){
						LOG("%s: out of memory while allocating channel..\n", __func__);
						enet_packet_destroy(event.packet);
						connection->disconnected = true;
						break;
					}
					new_channel->channel = event.channelID;
					new_channel->packet_list = init_list();
					new_channel->packet_offset = 0;
					if (new_channel->packet_list == NULL){
						LOG("%s: out of memory while allocating packet list for new channel..\n", __func__);
						free(new_channel);
						enet_packet_destroy(event.packet);
						connection->disconnected = true;
						break;
					}
					bool channel_add_status = list_push_front(connection->incoming_packets, new_channel);
					if (!channel_add_status){
						LOG("%s: out of memory while adding new channel to list..\n", __func__);
						free_list(new_channel->packet_list);
						free(new_channel);
						enet_packet_destroy(event.packet);
						connection->disconnected = true;
						break;
					}
					channel_itr = list_begin_itr(connection->incoming_packets);
				}
				struct channel *channel = (struct channel *)list_itr_get_data(channel_itr);
				bool packet_add_status = list_push_back(channel->packet_list, event.packet);
				if (!packet_add_status){
					LOG("%s: out of memory while inserting new packet to list..\n", __func__);
					enet_packet_destroy(event.packet);
					connection->disconnected = true;
					break;
				}
				break;
			}
			default:
				LOG("%s: unreachable codepath, debug this!\n", __func__);
				break;
		}
		itr = list_itr_next(itr);
	}

	if (events_processed == 0){
		return 1;
	}

	return 0;
}

int pump_enet(){
	lock_enet_mutex();
	int ret = _pump_enet();
	unlock_enet_mutex();
	return ret;
}

static struct channel *find_channel(struct connection *connection, int channel){
	void *channel_itr = list_begin_itr(connection->incoming_packets);
	while(channel_itr != NULL){
		struct channel *ch = list_itr_get_data(channel_itr);
		if (ch->channel == channel){
			break;
		}
		channel_itr = list_itr_next(channel_itr);
	}
	if (channel_itr == NULL){
		return NULL;
	}
	return (struct channel*)list_itr_get_data(channel_itr);
}

static int _recv_enet(void *handle, char *buf, int buf_size, int channel){
	if (connections == NULL){
		LOG("%s: enet is not initialized\n", __func__);
		return -1;
	}

	struct connection *connection = (struct connection *)handle;

	void *itr = find_connection_itr(connection);
	if (itr == NULL){
		LOG("%s: unknown handle %p..\n", __func__, handle);
		return -1;
	}

	if (connection->closed){
		LOG("%s: attempting to use a closed handle %p..\n", __func__, handle);
		return -1;
	}

	if (connection->disconnected){
		return 0;
	}

	struct channel *ch = find_channel(connection, channel);
	if (ch == NULL){
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	if (list_get_size(ch->packet_list) == 0){
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	int copied = 0;
	while (true){
		if (copied == buf_size){
			break;
		}
		ENetPacket *packet = (ENetPacket *)list_get_front(ch->packet_list);
		if (packet == NULL){
			break;
		}
		int buf_free = buf_size - copied;
		int packet_rem = packet->dataLength - ch->packet_offset;
		int to_copy = buf_free > packet_rem ? packet_rem : buf_free;
		memcpy(&buf[copied], &packet->data[ch->packet_offset], to_copy);
		copied += to_copy;
		ch->packet_offset += to_copy;
		if (ch->packet_offset == packet->dataLength){
			ch->packet_offset = 0;
			enet_packet_destroy(packet);
			list_pop_front(ch->packet_list);
		}
	}

	return copied;
}

int recv_enet(void *handle, char *buf, int buf_size, int channel){
	lock_enet_mutex();
	int ret = _recv_enet(handle, buf, buf_size, channel);
	unlock_enet_mutex();
	return ret;
}

static int _send_enet(void *handle, const char *buf, int buf_size, int channel, bool reliable){
	if (connections == NULL){
		LOG("%s: enet is not initialized\n", __func__);
		return -1;
	}

	struct connection *connection = (struct connection *)handle;

	void *itr = find_connection_itr(connection);
	if (itr == NULL){
		LOG("%s: unknown handle %p..\n", __func__, handle);
		return -1;
	}

	if (connection->closed){
		LOG("%s: attempting to use a closed handle %p..\n", __func__, handle);
		return -1;
	}

	if (connection->disconnected){
		return -1;
	}

	enet_uint32 flags = 0;
	if (reliable){
		flags |= ENET_PACKET_FLAG_RELIABLE;
	} else {
		flags |= ENET_PACKET_FLAG_UNSEQUENCED;
	}
	ENetPacket *packet = enet_packet_create(buf, buf_size, flags);
	if (packet == NULL){
		LOG("%s: out of memory while creating enet packet..\n", __func__);
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	int send_status = enet_peer_send(connection->peer, channel, packet);
	if (send_status != 0){
		LOG("%s: enet send failed..\n", __func__);
		enet_packet_destroy(packet);
		return -1;
	}

	return buf_size;
}

int send_enet(void *handle, const char *buf, int buf_size, int channel, bool reliable){
	lock_enet_mutex();
	int ret = _send_enet(handle, buf, buf_size, channel, reliable);
	unlock_enet_mutex();
	return ret;
}

static bool _is_disconnected_enet(void *handle){
	if (connections == NULL){
		LOG("%s: enet is not initialized\n", __func__);
		return true;
	}

	struct connection *connection = (struct connection *)handle;

	void *itr = find_connection_itr(connection);
	if (itr == NULL){
		LOG("%s: unknown handle %p..\n", __func__, handle);
		return true;
	}

	if (connection->closed){
		LOG("%s: attempting to use a closed handle %p..\n", __func__, handle);
		return true;
	}

	if (connection->disconnected){
		return true;
	}

	return false;
}

bool is_disconnected_enet(void *handle){
	lock_enet_mutex();
	bool ret = _is_disconnected_enet(handle);
	unlock_enet_mutex();
	return ret;
}

static int _peek_enet(void *handle, char *buf, int buf_size, int channel){\
	if (connections == NULL){
		LOG("%s: enet is not initialized\n", __func__);
		return -1;
	}

	struct connection *connection = (struct connection *)handle;

	void *itr = find_connection_itr(connection);
	if (itr == NULL){
		LOG("%s: unknown handle %p..\n", __func__, handle);
		return -1;
	}

	if (connection->closed){
		LOG("%s: attempting to use a closed handle %p..\n", __func__, handle);
		return -1;
	}

	if (connection->disconnected){
		return 0;
	}

	struct channel *ch = find_channel(connection, channel);
	if (ch == NULL){
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	if (list_get_size(ch->packet_list) == 0){
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	int copied = 0;
	void *packet_itr = list_begin_itr(ch->packet_list);
	int packet_offset = ch->packet_offset;
	while(true){
		if (copied == buf_size){
			break;
		}
		if (packet_itr == NULL){
			break;
		}
		int buf_free = buf_size - copied;
		ENetPacket *packet = (ENetPacket *)list_itr_get_data(packet_itr);
		int packet_rem = packet->dataLength - packet_offset;
		int to_copy = buf_free > packet_rem ? packet_rem : buf_free;
		memcpy(&buf[copied], &packet->data[packet_offset], to_copy);
		copied += to_copy;
		packet_offset += to_copy;
		if (packet_offset == packet->dataLength){
			packet_itr = list_itr_next(packet_itr);
			packet_offset = 0;
		}
	}

	return copied;
}

int peek_enet(void *handle, char *buf, int buf_size, int channel){
	lock_enet_mutex();
	int ret = _peek_enet(handle, buf, buf_size, channel);
	unlock_enet_mutex();
	return ret;
}
