#ifndef __ENET_H
#define __ENET_H

#include <stdbool.h>

#include "postoffice_client.h"

int init_enet();

void *connect_v6_enet(const struct aemu_post_office_sock6_addr *addr);
void *connect_v4_enet(const struct aemu_post_office_sock_addr *addr);
void close_enet(void *handle);

int recv_enet(void *handle, char *buf, int buf_size, int channel);
int send_enet(void *handle, const char *buf, int buf_size, int channel, bool reliable);

#endif
