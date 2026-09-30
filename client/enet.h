#ifndef __ENET_H
#define __ENET_H

#include <stdbool.h>

#include "postoffice_client.h"

int init_enet();

void *connect_v6_enet(const struct aemu_post_office_sock6_addr *addr); // returns a handle on success, NULL on error
void *connect_v4_enet(const struct aemu_post_office_sock_addr *addr); // returns a handle on success, NULL on error
void close_enet(void *handle);

int recv_enet(void *handle, char *buf, int buf_size, int channel); // filled size on success, AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK when there is no packet, AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY when buffer is too small, -1 on error
int send_enet(void *handle, const char *buf, int buf_size, int channel, bool reliable); // buffer size on success, -1 on error

int pump_enet(); // 0 on success, -1 on error, this has to be called regularly for enet processing

#endif
