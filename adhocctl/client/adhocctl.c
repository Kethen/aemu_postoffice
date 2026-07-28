#include <string.h>

#include "adhocctl.h"
#include "../../client/sock_impl.h"
#include "../../client/log_impl.h"
#include "../packets_v1.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

struct session {
	bool in_use;
	char game_code[9];
	char nickname[128];
	char mac[6];
	int sock_fd;
	int protocol_revision;
};

// the expectation right now is just, 1 session per process
struct session sessions[8] = {0};

#define SEND_PACKET(sock_fd, packet) { \
	bool abort = false; \
	int send_status = native_send_till_done(sock_fd, (char *)&packet, sizeof(packet), true, &abort); \
	if (send_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){ \
		return ADHOCCTL_CALL_WOULDBLOCK; \
	} \
	if (send_status == -1){ \
		return ADHOCCTL_CALL_ERROR; \
	} \
	return ADHOCCTL_CALL_SUCCESS; \
}

static enum adhocctl_call_status login_v1(int sock_fd, const char *game_code, const char *nickname, const char *mac){
	SceNetAdhocctlLoginPacketC2S packet = {0};
	packet.base.opcode = OPCODE_LOGIN;
	memcpy(packet.mac.data, mac, 6);
	memcpy(packet.name.data, nickname, 128);
	memcpy(packet.game.data, game_code, 9);

	SEND_PACKET(sock_fd, packet);
}

static void *create_adhocctl_session(void *addr, int addrlen, int protocol_revision, const char *game_code, const char *nickname, const char *mac, int channel){
	switch(protocol_revision){
		case 1:
			break;
		default:
			LOG("%s: unsupported protocol revision %d\n", __func__, protocol_revision);
			return NULL;
	}

	struct session *slot = NULL;
	for (int i = 0;i < ARRAY_SIZE(sessions);i++){
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


	slot->protocol_revision = protocol_revision;

	int sock_fd = native_connect_tcp_sock(addr, addrlen);
	if (sock_fd < 0){
		slot->in_use = false;
		return NULL;
	}
	slot->sock_fd = sock_fd;

	enum adhocctl_call_status call_status = ADHOCCTL_CALL_SUCCESS;
	switch(protocol_revision){
		case 1:
			call_status = login_v1(sock_fd, game_code, nickname, mac);
			if (call_status != ADHOCCTL_CALL_SUCCESS){
				slot->in_use = false;
				return NULL;
			}
			break;
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			slot->in_use = false;
			return NULL;
	}

	return slot;
}

void *create_adhocctl_session_v4(const struct adhocctl_addr_v4 *addr, int protocol_revision, const char *game_code, const char *nickname, const char *mac, int channel){
	struct aemu_post_office_sock_addr postoffice_addr = {
		.addr = addr->ip,
		.port = addr->port,
	};
	native_sock_addr native_addr = {0};
	to_native_sock_addr(&native_addr, &postoffice_addr);
	return create_adhocctl_session(&native_addr, sizeof(native_addr), protocol_revision, game_code, nickname, mac, channel);
}

void *create_adhocctl_session_v6(const struct adhocctl_addr_v6 *addr, int protocol_revision, const char *game_code, const char *nickname, const char *mac, int channel){
	struct aemu_post_office_sock6_addr postoffice_addr = {0};
	memcpy(postoffice_addr.addr, addr->ip, 16);
	postoffice_addr.port = addr->port;
	native_sock6_addr native_addr = {0};
	to_native_sock6_addr(&native_addr, &postoffice_addr);
	return create_adhocctl_session(&native_addr, sizeof(native_addr), protocol_revision, game_code, nickname, mac, channel);
}

void destroy_adhocctl_session(void *session){
	struct session *slot = (struct session *)session;

	native_close_tcp_sock(slot->sock_fd);
	slot->in_use = false;
}

static enum adhocctl_call_status ping_v1(int sock_fd){
	SceNetAdhocctlPacketBase packet = {
		.opcode = OPCODE_PING,
	};

	SEND_PACKET(sock_fd, packet);
}

enum adhocctl_call_status adhocctl_ping(void *session){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			return ping_v1(slot->sock_fd);
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			return ADHOCCTL_CALL_ERROR;
	}
}

static enum adhocctl_call_status connect_v1(int sock_fd, const char *group_name){
	SceNetAdhocctlConnectPacketC2S packet = {0};
	packet.base.opcode = OPCODE_CONNECT;
	memcpy(packet.group.data, group_name, 8);

	SEND_PACKET(sock_fd, packet);
}

enum adhocctl_call_status adhocctl_connect(void *session, const char *group_name){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			return connect_v1(slot->sock_fd, group_name);
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			return ADHOCCTL_CALL_ERROR;
	}
}

static enum adhocctl_call_status disconnect_v1(int sock_fd){
	SceNetAdhocctlPacketBase packet = {
		.opcode = OPCODE_DISCONNECT,
	};

	SEND_PACKET(sock_fd, packet);
}

enum adhocctl_call_status adhocctl_disconnect(void *session){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			return disconnect_v1(slot->sock_fd);
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			return ADHOCCTL_CALL_ERROR;
	}
}

static enum adhocctl_call_status scan_v1(int sock_fd){
	SceNetAdhocctlPacketBase packet = {
		.opcode = OPCODE_SCAN,
	};

	SEND_PACKET(sock_fd, packet);
}

enum adhocctl_call_status adhocctl_scan(void *session){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			return scan_v1(slot->sock_fd);
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			return ADHOCCTL_CALL_ERROR;
	}
}

static enum adhocctl_call_status chat_v1(int sock_fd, const char *message){
	SceNetAdhocctlChatPacketC2S packet = {0};
	packet.base.opcode = OPCODE_CHAT;
	strncpy(packet.message, message, 63);

	SEND_PACKET(sock_fd, packet);
}

enum adhocctl_call_status adhocctl_chat(void *session, const char *message){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			return chat_v1(slot->sock_fd, message);
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			return ADHOCCTL_CALL_ERROR;
	}
}

#undef SEND_PACKET

void get_event_v1(int sock_fd, struct adhocctl_event *event_out){
	SceNetAdhocctlPacketBase base_packet = {0};
	int peek_result = native_peek(sock_fd, (char *)&base_packet, sizeof(base_packet));
	#define CHECK_RESULT(res, expected_size) { \
		if (res == 0){ \
			LOG("%s: remote disconnected\n", __func__); \
			event_out->type = ADHOCCTL_EVENT_ERROR; \
			return; \
		} \
		if (res == -1){ \
			LOG("%s: recv errored\n", __func__); \
			event_out->type = ADHOCCTL_EVENT_ERROR; \
			return; \
		} \
		if (res == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK || res != expected_size){ \
			event_out->type = ADHOCCTL_EVENT_WOULD_BLOCK; \
			return; \
		} \
	}
	CHECK_RESULT(peek_result, sizeof(base_packet));

	memset(event_out, 0, sizeof(struct adhocctl_event));

	switch(base_packet.opcode){
		case OPCODE_SCAN:{
			SceNetAdhocctlScanPacketS2C packet = {0};
			int peek_result = native_peek(sock_fd, (char *)&packet, sizeof(packet));
			CHECK_RESULT(peek_result, sizeof(packet));
			int recv_result = native_recv(sock_fd, (char *)&packet, sizeof(packet));
			CHECK_RESULT(recv_result, sizeof(packet));
			event_out->type = ADHOCCTL_EVENT_SCAN;
			memcpy(event_out->scan.group_name, packet.group.data, 8);
			memcpy(event_out->scan.leader_mac, packet.mac.data, 6);
			return;
		}
		case OPCODE_SCAN_COMPLETE:{
			int recv_result = native_recv(sock_fd, (char *)&base_packet, sizeof(base_packet));
			CHECK_RESULT(recv_result, sizeof(base_packet));
			event_out->type = ADHOCCTL_EVENT_SCAN_COMPLETE;
			return;
		}
		case OPCODE_CONNECT:{
			SceNetAdhocctlConnectPacketS2C packet = {0};
			int peek_result = native_peek(sock_fd, (char *)&packet, sizeof(packet));
			CHECK_RESULT(peek_result, sizeof(packet));
			int recv_result = native_recv(sock_fd, (char *)&packet, sizeof(packet));
			CHECK_RESULT(recv_result, sizeof(packet));
			event_out->type = ADHOCCTL_EVENT_CONNECT;
			memcpy(event_out->connect.mac, packet.mac.data, 6);
			memcpy(event_out->connect.nickname, packet.name.data, 128);
			event_out->connect.id = packet.ip;
			return;
		}
		case OPCODE_CONNECT_BSSID:{
			SceNetAdhocctlConnectBSSIDPacketS2C packet = {0};
			int peek_result = native_peek(sock_fd, (char *)&packet, sizeof(packet));
			CHECK_RESULT(peek_result, sizeof(packet));
			int recv_result = native_recv(sock_fd, (char *)&packet, sizeof(packet));
			CHECK_RESULT(recv_result, sizeof(packet));
			event_out->type = ADHOCCTL_EVENT_LEADER_MAC;
			memcpy(event_out->leader_mac.mac, packet.mac.data, 6);
			return;
		}
		case OPCODE_DISCONNECT:{
			SceNetAdhocctlDisconnectPacketS2C packet = {0};
			int peek_result = native_peek(sock_fd, (char *)&packet, sizeof(packet));
			CHECK_RESULT(peek_result, sizeof(packet));
			int recv_result = native_recv(sock_fd, (char *)&packet, sizeof(packet));
			CHECK_RESULT(recv_result, sizeof(packet));
			event_out->type = ADHOCCTL_EVENT_DISCONNECT;
			event_out->disconnect.id = packet.ip;
			return;
		}
		case OPCODE_CHAT:{
			SceNetAdhocctlChatPacketS2C packet = {0};
			int peek_result = native_peek(sock_fd, (char *)&packet, sizeof(packet));
			CHECK_RESULT(peek_result, sizeof(packet));
			int recv_result = native_recv(sock_fd, (char *)&packet, sizeof(packet));
			CHECK_RESULT(recv_result, sizeof(packet));
			event_out->type = ADHOCCTL_EVENT_CHAT;
			memcpy(event_out->chat.nickname, packet.name.data, 128);
			memcpy(event_out->chat.message, packet.base.message, 64);
			return;
		}
		default:
			LOG("%s: remote sent unrecognized opcode %d\n", __func__, base_packet.opcode);
			event_out->type = ADHOCCTL_EVENT_ERROR;
			return;
	}
	#undef CHECK_RESULT
}

void adhocctl_get_event(void *session, struct adhocctl_event *event_out){
	struct session *slot = (struct session *)session;

	switch(slot->protocol_revision){
		case 1:
			get_event_v1(slot->sock_fd, event_out);
			break;
		default:
			LOG("%s: unreachable code path, debug this\n", __func__);
			break;
	}
}
