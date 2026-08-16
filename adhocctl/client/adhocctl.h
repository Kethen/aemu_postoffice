#ifndef __ADHOCCTL_H
#define __ADHOCCTL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct adhocctl_addr_v4 {
	uint32_t ip; // network order
	uint16_t port; // network order
};

struct adhocctl_addr_v6 {
	uint8_t ip[16]; // network order
	uint16_t port; // network order
};

// do not create session on multiple threads at the same time
// only protocol_revision 1 is currently supported
// game code has to be a buffer of 9 bytes, nickname has to be a buffer of 128 bytes, mac has to be a buffer of 6 bytes, channel does not do anything on protocol v1
void *create_adhocctl_session_v4(const struct adhocctl_addr_v4 *addr, int protocol_revision, const char *game_code, const char *nickname, const char *mac, int channel);
void *create_adhocctl_session_v6(const struct adhocctl_addr_v6 *addr, int protocol_revision, const char *game_code, const char *nickname, const char *mac, int channel);

void destroy_adhocctl_session(void *session);

enum adhocctl_event_type{
	ADHOCCTL_EVENT_SCAN,
	ADHOCCTL_EVENT_SCAN_COMPLETE,

	ADHOCCTL_EVENT_CONNECT,
	ADHOCCTL_EVENT_LEADER_MAC,
	ADHOCCTL_EVENT_DISCONNECT,

	ADHOCCTL_EVENT_CHAT,

	ADHOCCTL_EVENT_WOULD_BLOCK,
	ADHOCCTL_EVENT_ERROR,
};

struct adhocctl_event_scan{
	char group_name[8];
	char leader_mac[6];
};

struct adhocctl_event_scan_complete{

};

struct adhocctl_event_connect{
	char mac[6];
	uint32_t id;
	char nickname[128];
};

struct adhocctl_event_leader_mac{
	char mac[6];
};

struct adhocctl_event_disconnect{
	uint32_t id;
};

struct adhocctl_event_chat{
	char nickname[128];
	char message[1024];
};

struct adhocctl_event{
	int type;
	struct adhocctl_event_scan scan;
	struct adhocctl_event_scan_complete scan_complete;
	struct adhocctl_event_connect connect;
	struct adhocctl_event_leader_mac leader_mac;
	struct adhocctl_event_disconnect disconnect;
	struct adhocctl_event_chat chat;
};

enum adhocctl_call_status {
	ADHOCCTL_CALL_SUCCESS,
	ADHOCCTL_CALL_ERROR,
	ADHOCCTL_CALL_WOULDBLOCK,
};

// do not use the same session on multiple threads

// fetching events does not block
void adhocctl_get_event(void *session, struct adhocctl_event *event_out);

// these calls could block when send buffer gets full, depending on platform implementation of nonblock sockets
// keep alive
enum adhocctl_call_status adhocctl_ping(void *session);
// group name has to be abuffer of 8 bytes
enum adhocctl_call_status adhocctl_connect(void *session, const char *group_name);
enum adhocctl_call_status adhocctl_disconnect(void *session);
enum adhocctl_call_status adhocctl_scan(void *session);
// message has to be null terminated, v1 protocol trims message at 63 bytes
enum adhocctl_call_status adhocctl_chat(void *session, const char *message);

#ifdef __cplusplus
}
#endif

#endif
