#ifndef __SOCK_IMPL_COMMON_H
#define __SOCK_IMPL_COMMON_H

#include <stdbool.h>

#include "postoffice_client.h"

int native_connect_tcp_sock(const struct aemu_postoffice_sock_addr *addr4, const struct aemu_postoffice_sock6_addr *addr6);
int native_close_tcp_sock(int sock);
int native_send(int fd, const char *buf, int len);
int native_recv(int fd, char *buf, int len);
int native_peek(int fd, char *buf, int len);
bool native_send_buf_not_full(int fd);
bool native_hung_up(int fd);

#endif
