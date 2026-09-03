#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <windows.h>

#include "native_socket.h"
#include "log.h"

#include <string>

#include <stdint.h>

namespace aemu_postoffice_server {

int native_recv(int fd, void *buf, int buflen){
	return recv(fd, (char *)buf, buflen, 0);
}

int native_send(int fd, void *buf, int buflen){
	return send(fd, (const char *)buf, buflen, 0);
}

int native_get_last_socket_error(){
	return WSAGetLastError();
}

bool native_error_is_would_block(int error){
	return error == WSAEWOULDBLOCK;
}

bool native_error_is_no_mem(int error){
	return error == WSAENOBUFS || error == WSA_NOT_ENOUGH_MEMORY;
}

bool native_error_is_emfile(int error){
	return error == WSAEMFILE;
}

AddrFamily get_addr_family(std::string ip){
	int family = AF_INET6;
	struct in6_addr addr6;
	struct in_addr addr4;
	if (inet_pton(AF_INET6, ip.c_str(), (void *)&addr6) == 1){
		return AddrFamily::IPV6;
	}
	if (inet_pton(AF_INET, ip.c_str(), (void *)&addr4) == 1){
		return AddrFamily::IPV4;
	}
	return AddrFamily::UNKNOWN;
}

uint32_t native_parse_ipv4(std::string ip){
	struct in_addr addr4;
	int parse_result = inet_pton(AF_INET, ip.c_str(), (void *)&addr4);
	if (parse_result != 1){
		return 0xffffffff;
	}
	return addr4.s_addr;
}

static void init_winsock(){
	static bool initialized = false;
	if (initialized){
		return;
	}
	initialized = true;
	WSADATA wsa_data;
	int err = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	if (err != 0){
		LOG("%s: warning: WSAStartup failed, it might have been initialized already\n", __func__);
	}
}

int native_tcp_listen(std::string ip, uint16_t port){
	init_winsock();

	struct sockaddr_in6 addr6 = {0};
	struct sockaddr_in addr4 = {0};

	addr6.sin6_family = AF_INET6;
	addr4.sin_family = AF_INET;

	addr6.sin6_port = htons(port);
	addr4.sin_port = htons(port);

	int family = AF_INET6;

	if (inet_pton(AF_INET6, ip.c_str(), &addr6.sin6_addr) == -1){
		family = AF_INET;
		if (inet_pton(AF_INET, ip.c_str(), &addr4.sin_addr) == -1){
			return -2;
		}
	}

	SOCKET win_sock_fd = socket(family, SOCK_STREAM, 0);
	if (win_sock_fd == INVALID_SOCKET){
		return -1;
	}
	int sock_fd = win_sock_fd;

	if (family == AF_INET6){
		DWORD v6_only_opt = 0;
		setsockopt(sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6_only_opt, sizeof(v6_only_opt));
	}

	BOOL reuse_opt = TRUE;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse_opt, sizeof(reuse_opt));

	void *addr = family == AF_INET6 ? (void *)&addr6 : (void *)&addr4;
	int addr_len = family == AF_INET6 ? sizeof(addr6) : sizeof(addr4);
	int bind_result = bind(sock_fd, (const sockaddr *)addr, addr_len);
	if (bind_result == SOCKET_ERROR){
		int err = WSAGetLastError();
		LOG("%s: bind failed, 0x%x\n", __func__, err);
		return -1;
	}

	int listen_result = listen(sock_fd, 1000);
	if (listen_result == SOCKET_ERROR){
		int err = WSAGetLastError();
		LOG("%s: listen failed, 0x%x\n", __func__, err);
		return -1;
	}

	u_long nbio = 1;
	ioctlsocket(sock_fd, FIONBIO, &nbio);

	return sock_fd;
}

int native_accept(int sock_fd, std::string *peer_addr, uint16_t *peer_port){
	struct sockaddr_in6 addr = {0};

	socklen_t addr_len = sizeof(addr);
	SOCKET accept_result_win = accept(sock_fd, (sockaddr *)&addr, &addr_len);
	if (accept_result_win == INVALID_SOCKET){
		return -1;
	}
	int accept_result = accept_result_win;

	u_long nbio = 1;
	ioctlsocket(accept_result, FIONBIO, &nbio);

	DWORD opt_tcp_no_delay = 1;
	setsockopt(accept_result, IPPROTO_TCP, TCP_NODELAY, (const char *)&opt_tcp_no_delay, sizeof(opt_tcp_no_delay));

	DWORD send_recv_buf_size = 64 * 1024;
	setsockopt(accept_result, SOL_SOCKET, SO_SNDBUF, (const char *)&send_recv_buf_size, sizeof(send_recv_buf_size));
	setsockopt(accept_result, SOL_SOCKET, SO_RCVBUF, (const char *)&send_recv_buf_size, sizeof(send_recv_buf_size));

	char addr_buf[128] = {0};
	uint16_t port = 0;
	if (addr.sin6_family == AF_INET6){
		inet_ntop(AF_INET6, &addr.sin6_addr, addr_buf, sizeof(addr_buf));
		port = addr.sin6_port;
	}else{
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
		inet_ntop(AF_INET, &addr4->sin_addr, addr_buf, sizeof(addr_buf));
		port = addr4->sin_port;
	}

	*peer_addr = std::string(addr_buf);
	*peer_port = port;

	return accept_result;
}

void native_close(int sock_fd){
	closesocket(sock_fd);
}

}
