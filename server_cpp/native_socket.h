#pragma once

#include <stdint.h>

#include <string>

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
int native_tcp_listen(std::string ip, uint16_t port);
int native_accept(int sock_fd, std::string *peer_addr, uint16_t *peer_port);
AddrFamily get_addr_family(std::string ip);
uint32_t native_parse_ipv4(std::string ip);

}
