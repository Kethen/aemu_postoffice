// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stdint.h>

#include <string>
#include <vector>

// socket ops are supposed to be non block

namespace aemu_postoffice_server {

enum class AddrFamily {
	IPV4,
	IPV6,
	UNKNOWN
};

void native_close(int fd);
int native_recv(int fd, void *buf, int buflen);
int native_send(int fd, void *buf, int buflen);
int native_get_last_socket_error();
bool native_error_is_would_block(int error);
bool native_error_is_no_mem(int error);
bool native_error_is_emfile(int error);
// errors from accept that concern only the connection being accepted
bool native_error_is_accept_transient(int error);
int native_tcp_listen(std::string ip, uint16_t port);
int native_accept(int sock_fd, std::string *peer_addr, uint16_t *peer_port);
// waits until one of read_fds is readable, one of write_fds is writable, or timeout_ms has passed
void native_wait_multiple(const std::vector<int> &read_fds, const std::vector<int> &write_fds, int timeout_ms);
AddrFamily get_addr_family(std::string ip);
uint32_t native_parse_ipv4(std::string ip);

}
