#ifndef __ENET_H
#define __ENET_H

#include <stdbool.h>

#include "postoffice_client.h"
#include "mutex_impl.h"

int init_enet(); // returns 0 on success, -1 on error
void deinit_enet();

void *connect_enet(const struct aemu_postoffice_sock_addr *addr4, const struct aemu_postoffice_sock6_addr *addr6, int channels); // returns a handle on success, NULL on error
void close_enet(void *handle);

int recv_enet(void *handle, char *buf, int buf_size, int channel); // filled size on success, AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK when there is no packet, 0 on remote disconnected, -1 on error, note that this wrapper operates in stream mode
int peek_enet(void *handle, char *buf, int buf_size, int channel); // filled size on success, AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK when there is no packet, 0 on remote disconnected, -1 on error
int send_enet(void *handle, const char *buf, int buf_size, int channel, bool reliable); // buffer size on success, AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK when a new packet cannot be allocated, -1 on error

bool is_disconnected_enet(void *handle);

int pump_enet(); // 0 on success, -1 on error, this has to be called regularly for enet processing

#endif
