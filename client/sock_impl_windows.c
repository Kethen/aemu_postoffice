#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <profileapi.h>

#include <string.h>
#include <stdio.h>

#include "postoffice_client.h"
#include "sock_impl.h"
#include "log_impl.h"

typedef struct sockaddr_in native_sock_addr;
typedef struct sockaddr_in6 native_sock6_addr;

static void to_native_sock_addr(native_sock_addr *dst, const struct aemu_postoffice_sock_addr *src){
	memset(dst, 0, sizeof(native_sock_addr));
	dst->sin_family = AF_INET;
	dst->sin_addr.s_addr = src->addr;
	dst->sin_port = src->port;
}

static void to_native_sock6_addr(native_sock6_addr *dst, const struct aemu_postoffice_sock6_addr *src){
	memset(dst, 0, sizeof(native_sock6_addr));
	dst->sin6_family = AF_INET6;
	dst->sin6_port = src->port;
	memcpy(dst->sin6_addr.s6_addr, src->addr, 16);
}

static void init_winsock2(){
	static bool initialized = false;
	if (!initialized){
		initialized = true;
		WSADATA data;
		int init_result = WSAStartup(MAKEWORD(2,2), &data);
		if (init_result != 0){
			printf("%s: warning: WSAStartup seems to have failed, %d\n", __func__, init_result);
		}
	}
}

static int connect_with_timeout(int sock, native_sock_addr *addr, int addrlen, int timeout_ms, int *error){
	u_long ioctlopt = 1;
	ioctlsocket(sock, FIONBIO, &ioctlopt);

	int ret = 0;

	LARGE_INTEGER begin = {0};
	QueryPerformanceCounter(&begin);
	LARGE_INTEGER ticks_per_seconds = {0};
	QueryPerformanceFrequency(&ticks_per_seconds);

	while(1){
		int result = connect(sock, (struct sockaddr *)addr, addrlen);
		if (result == 0){
			ret = 0;
			break;
		}
		if (result == -1){
			LARGE_INTEGER now = {0};
			QueryPerformanceCounter(&now);
			int ms_since_begin = (now.QuadPart - begin.QuadPart) * 1000 / ticks_per_seconds.QuadPart;
			if (ms_since_begin > timeout_ms){
				*error = WSAETIMEDOUT;
				ret = -1;
				break;
			}

			*error = WSAGetLastError();
			// it was found out together with @hrydgard that after using WinHttp, it could also throw WSAEINVAL for WSAEALREADY
			if (*error == WSAEWOULDBLOCK || *error == WSAEALREADY || *error == WSAEINVAL){
				// in progress
				Sleep(1);
				continue;
			}
			if (*error == WSAEISCONN){
				// connected
				*error = 0;
				ret = 0;
				break;
			}
			ret = -1;
			break;
		}
	}

	// just for completness, NBIO is used on the socket after connection anyway
	ioctlopt = 0;
	ioctlsocket(sock, FIONBIO, &ioctlopt);
	return ret;
}

int native_connect_tcp_sock(const struct aemu_postoffice_sock_addr *addr4, const struct aemu_postoffice_sock6_addr *addr6){
	init_winsock2();

	native_sock_addr native_addr4;
	native_sock6_addr native_addr6;
	int addrlen = 0;
	native_sock_addr *addr = NULL;
	if (addr4 != NULL){
		to_native_sock_addr(&native_addr4, addr4);
		addr = &native_addr4;
		addrlen = sizeof(native_addr4);
	} else {
		to_native_sock6_addr(&native_addr6, addr6);
		addr = (native_sock_addr *)&native_addr6;
		addrlen = sizeof(native_addr6);
	}
	SOCKET win_sock = socket(addr->sin_family, SOCK_STREAM, 0);
	if (win_sock == INVALID_SOCKET){
		LOG("%s: failed creating socket, %d\n", __func__, WSAGetLastError());
		return AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
	}
	int sock = win_sock;

	// XXX need to simulate timeout on windows, there's no sockopt for that
	// this also restricts latency to 500ms, if a server is even further away, connection won't be possible

	// Connect
	int error = 0;
	int connect_status = connect_with_timeout(sock, addr, addrlen, 5000, &error);
	if (connect_status == -1){
		LOG("%s: failed connecting, %d\n", __func__, error);
		closesocket(sock);
		return AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
	}

	// Set socket options
	int sockopt = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&sockopt, sizeof(sockopt));
	u_long ioctlopt = 1;
	ioctlsocket(sock, FIONBIO, &ioctlopt);

	sockopt = 2626560;
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&sockopt, sizeof(sockopt));
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&sockopt, sizeof(sockopt));

	#if 0
	// Show some socket options
	int opt_len = sizeof(sockopt);
	sockopt = 0;
	int get_ret = getsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&sockopt, &opt_len);
	LOG("%s: TCP_NODELAY is %d (0x%x)\n", __func__, sockopt, get_ret == -1 ? WSAGetLastError() : 0);

	opt_len = sizeof(sockopt);
	sockopt = 0;
	get_ret = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&sockopt, &opt_len);
	LOG("%s: SO_SNDBUF is %d (0x%x)\n", __func__, sockopt, get_ret == -1 ? WSAGetLastError() : 0);

	opt_len = sizeof(sockopt);
	sockopt = 0;
	get_ret = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&sockopt, &opt_len);
	LOG("%s: SO_RCVBUF is %d (0x%x)\n", __func__, sockopt, get_ret == -1 ? WSAGetLastError() : 0);
	#endif

	return sock;
}

int native_send(int fd, const char *buf, int len){
	int write_status = send(fd, buf, len, 0);
	if (write_status == -1){
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS){
			return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
		}
		LOG("%s: failed sending, %d\n", __func__, err);
		return write_status;
	}
	return write_status;
}

int native_recv(int fd, char *buf, int len){
	int recv_status = recv(fd, buf, len, 0);
	if (recv_status == 0){
		return recv_status;
	}
	if (recv_status < 0){
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS){
			return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
		}
		// Other errors
		LOG("%s: failed receving, %d\n", __func__, err);
		return recv_status;
	}
	return recv_status;
}

int native_close_tcp_sock(int sock){
	return closesocket(sock);
}

int native_peek(int fd, char *buf, int len){
	int read_result = recv(fd, buf, len, MSG_PEEK);
	if (read_result == 0){
		return 0;
	}
	if (read_result == -1){
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS){
			return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
		}
		LOG("%s: failed peeking, %d\n", __func__, WSAGetLastError());
		return -1;
	}
	return read_result;
}

bool native_send_buf_not_full(int fd){
	WSAPOLLFD pfd;
	pfd.fd = fd;
	pfd.events = POLLWRNORM;
	pfd.revents = 0;
	WSAPoll(&pfd, 1, 0);
	if (pfd.revents & POLLHUP){
		return false;
	}
	if (pfd.revents & POLLWRNORM){
		return true;
	}
	return false;
}

bool native_hung_up(int fd){
	uint8_t buf;
	int peek_result = native_peek(fd, (char *)&buf, sizeof(buf));
	if (peek_result == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK ||
		peek_result == sizeof(buf)
	){
		return false;
	}
	return true;
}
