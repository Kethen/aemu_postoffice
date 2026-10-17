#include <string.h>

#include "adhocctl.h"
#include "adhocctl_mem.h"
#include "../../client/sock_impl.h"
#include "../../client/enet.h"
#include "../../client/log_impl.h"
#include "../packets_v1.h"
#include "../../client/delay_impl.h"

// TODO finish enet mode for adhocctl

#define ABORTED -100

static bool connect_wrapped(const struct adhocctl_addr_v4 *addr4, const struct adhocctl_addr_v4 *bind_addr4, const struct adhocctl_addr_v6 *addr6, const struct adhocctl_addr_v6 *bind_addr6, bool enet, int *sock, void **enet_handle, bool (*abort_connection)(void *arg), void *abort_connection_arg, const char *caller_name){
	struct aemu_postoffice_sock_addr poaddr4 = {0};
	struct aemu_postoffice_sock6_addr poaddr6 = {0};
	struct aemu_postoffice_sock_addr bind_poaddr4 = {0};
	struct aemu_postoffice_sock6_addr bind_poaddr6 = {0};
	struct aemu_postoffice_sock_addr *_poaddr4 = NULL;
	struct aemu_postoffice_sock6_addr *_poaddr6 = NULL;
	struct aemu_postoffice_sock_addr *_bind_poaddr4 = NULL;
	struct aemu_postoffice_sock6_addr *_bind_poaddr6 = NULL;

	if (addr4 != NULL){
		poaddr4.addr = addr4->ip;
		poaddr4.port = addr4->port;
		_poaddr4 = &poaddr4;
	} else {
		memcpy(poaddr6.addr, addr6->ip, 16);
		poaddr6.port = addr6->port;
		_poaddr6 = &poaddr6;
	}

	if (bind_addr4 != NULL){
		bind_poaddr4.addr = bind_addr4->ip;
		bind_poaddr4.port = bind_addr4->port;
		_bind_poaddr4 = &bind_poaddr4;
	}

	if (bind_addr6 != NULL){
		memcpy(bind_poaddr6.addr, bind_addr6->ip, 16);
		bind_poaddr6.port = bind_addr6->port;
		_bind_poaddr6 = &bind_poaddr6;
	}

	if (!enet){
		enet_handle[0] = NULL;
		sock[0] = native_connect_tcp_sock(_poaddr4, _bind_poaddr4, _poaddr6, _bind_poaddr6, abort_connection, abort_connection_arg);
		if (sock[0] < 0){
			LOG("%s: tcp connection failed\n", caller_name);
			return false;
		}
	} else {
		sock[0] = 0;
		enet_handle[0] = connect_enet(_poaddr4, _poaddr6, 1, abort_connection, abort_connection_arg);
		if (enet_handle[0] == NULL){
			LOG("%s: enet connection failed\n", caller_name);
			return false;
		}
	}
	return true;
}

static void close_wrapped(int sock, void *enet_handle){
	if (enet_handle == NULL){
		native_close_tcp_sock(sock);
		return;
	}
	close_enet(enet_handle);
}

static int send_wrapped(int sock, void *enet_handle, const char *buf, int len){
	if (enet_handle == NULL){
		return native_send(sock, buf, len);
	}

	return send_enet(enet_handle, buf, len, 0, true);
}

static int recv_wrapped(int sock, void *enet_handle, char *buf, int len){
	if (enet_handle == NULL){
		return native_recv(sock, buf, len);
	}

	return recv_enet(enet_handle, buf, len, 0);
}

static int peek_wrapped(int sock, void *enet_handle, char *buf, int len){
	if (enet_handle == NULL){
		return native_peek(sock, buf, len);
	}
	return peek_enet(enet_handle, buf, len, 0);
}

static int send_till_done(int fd, void *enet_handle, const char *buf, int len, bool non_block, bool *abort){
	int write_offset = 0;
	while(write_offset != len){
		if (*abort){
			return ABORTED;
		}
		int write_status = send_wrapped(fd, enet_handle, &buf[write_offset], len - write_offset);
		if (write_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
			if (non_block && write_offset == 0){
				delay(0);
				return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
			}
			delay(0);
			continue;
		}
		if (write_status == -1){
			return write_status;
		}
		write_offset += write_status;
	}
	return write_offset;
}

#define SEND_PACKET(sock_fd, enet_handle, packet) { \
	bool abort = false; \
	int send_status = send_till_done(sock_fd, enet_handle, (char *)&packet, sizeof(packet), true, &abort); \
	if (send_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){ \
		return ADHOCCTL_CALL_WOULDBLOCK; \
	} \
	if (send_status == -1){ \
		return ADHOCCTL_CALL_ERROR; \
	} \
	return ADHOCCTL_CALL_SUCCESS; \
}

static enum adhocctl_call_status login_v1(int sock_fd, void *enet_handle, const char *game_code, const char *nickname, const char *mac){
	SceNetAdhocctlLoginPacketC2S packet = {0};
	packet.base.opcode = OPCODE_LOGIN;
	memcpy(packet.mac.data, mac, 6);
	memcpy(packet.name.data, nickname, 127);
	memcpy(packet.game.data, game_code, 9);

	SEND_PACKET(sock_fd, enet_handle, packet);
}

static void *create_adhocctl_v1_session(const struct adhocctl_addr_v4 *addr4, const struct adhocctl_addr_v4 *bind_addr4, const struct adhocctl_addr_v6 *addr6, const struct adhocctl_addr_v6 *bind_addr6, const char *game_code, const char *nickname, const char *mac, bool enet, bool (*abort_connection)(void *arg), void *abort_connection_arg){
	struct session *slot = NULL;
	for (int i = 0;i < *num_sessions;i++){
		if (!sessions[i].in_use){
			slot = &sessions[i];
			memset(slot, 0, sizeof(struct session));
			slot->in_use = true;
			break;
		}
	}

	if (slot == NULL){
		return NULL;
	}

	slot->protocol_revision = 1;

	bool connected = connect_wrapped(addr4, bind_addr4, addr6, bind_addr6, enet, &slot->sock_fd, &slot->enet_handle, abort_connection, abort_connection_arg, __func__);
	if (!connected){
		LOG("%s: failed creating connection to adhoccl server\n", __func__);
		slot->in_use = false;
		return NULL;
	}

	enum adhocctl_call_status call_status = login_v1(slot->sock_fd, slot->enet_handle, game_code, nickname, mac);
	if (call_status != ADHOCCTL_CALL_SUCCESS){
		LOG("%s: failed sending login packet\n", __func__);
		slot->in_use = false;
		return NULL;
	}

	return slot;
}

void *create_adhocctl_v1_session_v4(const struct adhocctl_addr_v4 *addr, const struct adhocctl_addr_v4 *bind_addr, const char *game_code, const char *nickname, const char *mac, bool enet, bool (*abort_connection)(void *arg), void *abort_connection_arg){
	return create_adhocctl_v1_session(addr, bind_addr, NULL, NULL, game_code, nickname, mac, enet, abort_connection, abort_connection_arg);
}

void *create_adhocctl_v1_session_v6(const struct adhocctl_addr_v6 *addr, const struct adhocctl_addr_v6 *bind_addr, const char *game_code, const char *nickname, const char *mac, bool enet, bool (*abort_connection)(void *arg), void *abort_connection_arg){
	return create_adhocctl_v1_session(NULL, NULL, addr, bind_addr, game_code, nickname, mac, enet, abort_connection, abort_connection_arg);
}

void destroy_adhocctl_session(void *session){
	struct session *slot = (struct session *)session;

	close_wrapped(slot->sock_fd, slot->enet_handle);
	slot->in_use = false;
}

static enum adhocctl_call_status ping_v1(int sock_fd, void *enet_handle){
	SceNetAdhocctlPacketBase packet = {
		.opcode = OPCODE_PING,
	};

	SEND_PACKET(sock_fd, enet_handle, packet);
}

enum adhocctl_call_status adhocctl_ping(void *session){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			return ping_v1(slot->sock_fd, slot->enet_handle);
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			return ADHOCCTL_CALL_ERROR;
	}
}

static enum adhocctl_call_status connect_v1(int sock_fd, void *enet_handle, const char *group_name){
	SceNetAdhocctlConnectPacketC2S packet = {0};
	packet.base.opcode = OPCODE_CONNECT;
	memcpy(packet.group.data, group_name, 8);

	SEND_PACKET(sock_fd, enet_handle, packet);
}

enum adhocctl_call_status adhocctl_connect(void *session, const char *group_name){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			return connect_v1(slot->sock_fd, slot->enet_handle, group_name);
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			return ADHOCCTL_CALL_ERROR;
	}
}

static enum adhocctl_call_status disconnect_v1(int sock_fd, void *enet_handle){
	SceNetAdhocctlPacketBase packet = {
		.opcode = OPCODE_DISCONNECT,
	};

	SEND_PACKET(sock_fd, enet_handle, packet);
}

enum adhocctl_call_status adhocctl_disconnect(void *session){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			return disconnect_v1(slot->sock_fd, slot->enet_handle);
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			return ADHOCCTL_CALL_ERROR;
	}
}

static enum adhocctl_call_status scan_v1(int sock_fd, void *enet_handle){
	SceNetAdhocctlPacketBase packet = {
		.opcode = OPCODE_SCAN,
	};

	SEND_PACKET(sock_fd, enet_handle, packet);
}

enum adhocctl_call_status adhocctl_scan(void *session){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			return scan_v1(slot->sock_fd, slot->enet_handle);
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			return ADHOCCTL_CALL_ERROR;
	}
}

static enum adhocctl_call_status chat_v1(int sock_fd, void *enet_handle, const char *message){
	SceNetAdhocctlChatPacketC2S packet = {0};
	packet.base.opcode = OPCODE_CHAT;
	strncpy(packet.message, message, 63);

	SEND_PACKET(sock_fd, enet_handle, packet);
}

enum adhocctl_call_status adhocctl_chat(void *session, const char *message){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			return chat_v1(slot->sock_fd, slot->enet_handle, message);
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			return ADHOCCTL_CALL_ERROR;
	}
}

#undef SEND_PACKET

void get_event_v1(int sock_fd, void *enet_handle, struct adhocctl_event *event_out){
	SceNetAdhocctlPacketBase base_packet = {0};
	int peek_result = peek_wrapped(sock_fd, enet_handle, (char *)&base_packet, sizeof(base_packet));
	#define CHECK_RESULT(res, expected_size) { \
		if (res == 0){ \
			LOG("%s: remote disconnected\n", __func__); \
			event_out->type = ADHOCCTL_CLIENT_EVENT_ERROR; \
			return; \
		} \
		if (res == -1){ \
			LOG("%s: recv errored\n", __func__); \
			event_out->type = ADHOCCTL_CLIENT_EVENT_ERROR; \
			return; \
		} \
		if (res == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK || res != expected_size){ \
			event_out->type = ADHOCCTL_CLIENT_EVENT_WOULD_BLOCK; \
			return; \
		} \
	}
	CHECK_RESULT(peek_result, sizeof(base_packet));

	memset(event_out, 0, sizeof(struct adhocctl_event));

	switch(base_packet.opcode){
		case OPCODE_SCAN:{
			SceNetAdhocctlScanPacketS2C packet = {0};
			int peek_result = peek_wrapped(sock_fd, enet_handle, (char *)&packet, sizeof(packet));
			CHECK_RESULT(peek_result, sizeof(packet));
			int recv_result = recv_wrapped(sock_fd, enet_handle, (char *)&packet, sizeof(packet));
			CHECK_RESULT(recv_result, sizeof(packet));
			event_out->type = ADHOCCTL_CLIENT_EVENT_SCAN;
			memcpy(event_out->scan.group_name, packet.group.data, 8);
			memcpy(event_out->scan.leader_mac, packet.mac.data, 6);
			return;
		}
		case OPCODE_SCAN_COMPLETE:{
			int recv_result = recv_wrapped(sock_fd, enet_handle, (char *)&base_packet, sizeof(base_packet));
			CHECK_RESULT(recv_result, sizeof(base_packet));
			event_out->type = ADHOCCTL_CLIENT_EVENT_SCAN_COMPLETE;
			return;
		}
		case OPCODE_CONNECT:{
			SceNetAdhocctlConnectPacketS2C packet = {0};
			int peek_result = peek_wrapped(sock_fd, enet_handle, (char *)&packet, sizeof(packet));
			CHECK_RESULT(peek_result, sizeof(packet));
			int recv_result = recv_wrapped(sock_fd, enet_handle, (char *)&packet, sizeof(packet));
			CHECK_RESULT(recv_result, sizeof(packet));
			event_out->type = ADHOCCTL_CLIENT_EVENT_CONNECT;
			memcpy(event_out->connect.mac, packet.mac.data, 6);
			memcpy(event_out->connect.nickname, packet.name.data, 127);
			event_out->connect.id = packet.ip;
			return;
		}
		case OPCODE_CONNECT_BSSID:{
			SceNetAdhocctlConnectBSSIDPacketS2C packet = {0};
			int peek_result = peek_wrapped(sock_fd, enet_handle, (char *)&packet, sizeof(packet));
			CHECK_RESULT(peek_result, sizeof(packet));
			int recv_result = recv_wrapped(sock_fd, enet_handle, (char *)&packet, sizeof(packet));
			CHECK_RESULT(recv_result, sizeof(packet));
			event_out->type = ADHOCCTL_CLIENT_EVENT_LEADER_MAC;
			memcpy(event_out->leader_mac.mac, packet.mac.data, 6);
			return;
		}
		case OPCODE_DISCONNECT:{
			SceNetAdhocctlDisconnectPacketS2C packet = {0};
			int peek_result = peek_wrapped(sock_fd, enet_handle, (char *)&packet, sizeof(packet));
			CHECK_RESULT(peek_result, sizeof(packet));
			int recv_result = recv_wrapped(sock_fd, enet_handle, (char *)&packet, sizeof(packet));
			CHECK_RESULT(recv_result, sizeof(packet));
			event_out->type = ADHOCCTL_CLIENT_EVENT_DISCONNECT;
			event_out->disconnect.id = packet.ip;
			return;
		}
		case OPCODE_CHAT:{
			SceNetAdhocctlChatPacketS2C packet = {0};
			int peek_result = peek_wrapped(sock_fd, enet_handle, (char *)&packet, sizeof(packet));
			CHECK_RESULT(peek_result, sizeof(packet));
			int recv_result = recv_wrapped(sock_fd, enet_handle, (char *)&packet, sizeof(packet));
			CHECK_RESULT(recv_result, sizeof(packet));
			event_out->type = ADHOCCTL_CLIENT_EVENT_CHAT;
			memcpy(event_out->chat.nickname, packet.name.data, 127);
			memcpy(event_out->chat.message, packet.base.message, 64);
			return;
		}
		default:
			LOG("%s: remote sent unrecognized opcode %d\n", __func__, base_packet.opcode);
			event_out->type = ADHOCCTL_CLIENT_EVENT_ERROR;
			return;
	}
	#undef CHECK_RESULT
}

void adhocctl_get_event(void *session, struct adhocctl_event *event_out){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			get_event_v1(slot->sock_fd, slot->enet_handle, event_out);
			break;
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			break;
	}
}
