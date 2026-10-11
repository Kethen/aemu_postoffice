#ifndef __PSP_ENET_SHIM_H
#define __PSP_ENET_SHIM_H

#define AI_NUMERICHOST (1)
#define NI_NAMEREQD (1)

#define EAI_FAIL -100
#define EAI_NONAME -101

#include "log_impl.h"

#include <stdint.h>
#include <stdarg.h>

#include <fcntl.h>

#include <pspnet_inet.h>
#include <pspthreadman.h>
#include <pspintrman.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define SCE_NET_INET_POLLIN 0x0001
#define SCE_NET_INET_POLLOUT 0x0004
#define POLLOUT SCE_NET_INET_POLLOUT
#define POLLIN SCE_NET_INET_POLLIN

typedef struct pollfd {
	int fd;
	short events;
	short revents;
};

struct addrinfo{
	int ai_flags;
	int ai_family;
	int ai_addrlen;
	struct sockaddr *ai_addr;
	struct addrinfo *ai_next;
};

static struct addrinfo dummy_res = {0};

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res){
	LOG("%s: this is a stub, there is no implmentation here\n", __func__);
	res[0] = &dummy_res;
	return EAI_FAIL;
}

void freeaddrinfo(struct addrinfo *res){
	LOG("%s: this is a stub, there is no implmentation here\n", __func__);
}

int getnameinfo(const struct sockaddr *addr, int addrlen, char *host, int hostlen, char *serv, int servlen, int flags){
	LOG("%s: this is a stub, there is no implmentation here\n", __func__);
	return EAI_FAIL;
}

int sceNetInetPoll(struct pollfd *fds, int nfds, int timeout);
#define poll(fds, nfds, timeout) sceNetInetPoll(fds, nfds, timeout)
#define socket(domain, type, protocol) sceNetInetSocket(domain, type, protocol)
#define close(sock) sceNetInetClose(sock)
#define bind(sock, addr, addrlen) sceNetInetBind(sock, addr, addrlen)
#define getsockname(sock, addr, addrlen) sceNetInetGetsockname(sock, addr, addrlen)
#define listen(sock, backlog) sceNetInetListen(sock, backlog)
#define connect(sock, serv_addr, addrlen) sceNetInetConnect(sock, serv_addr, addrlen)
#define accept(sock, addr, addrlen) sceNetInetAccept(sock, addr, addrlen)
#define shutdown(sock, how) sceNetInetShutdown(sock, how)
#define sendmsg(sock, msg, flags) sceNetInetSendmsg(sock, msg, flags)
#define recvmsg(sock, msg, flags) sceNetInetRecvmsg(sock, msg, flags)
int select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout){
	struct SceNetInetTimeval sce_timeout = {
		.tv_sec = timeout->tv_sec,
		.tv_usec = timeout->tv_usec
	};
	int ret = sceNetInetSelect(n, readfds, writefds, exceptfds, &sce_timeout);
	timeout->tv_sec = sce_timeout.tv_sec;
	timeout->tv_usec = sce_timeout.tv_usec;
	return ret;
}
#define SO_NBIO 0x1009
int fcntl(int fd, int op, ...){
	if (op == F_GETFL){
		int cur_opt;
		socklen_t cur_opt_len = sizeof(cur_opt);
		sceNetInetGetsockopt(fd, SOL_SOCKET, SO_NBIO, &cur_opt, &cur_opt_len);
		return cur_opt ? O_NONBLOCK : 0;
	} else if (op == F_SETFL) {
		va_list args;
		va_start(args, op);
		int val = va_arg(args, int);
		va_end(args);
		if (val == O_NONBLOCK){
			val = 1;
		} else {
			val = 0;
		}
		sceNetInetSetsockopt(fd, SOL_SOCKET, SO_NBIO, &val, sizeof(val));
		return 0;
	}
	LOG("%s: fcntl op 0x%x is not implemented\n", __func__, op);
	return 0;
}
#define setsockopt(sock, level, optname, optval, optlen) sceNetInetSetsockopt(sock, level, optname, optval, optlen)
#define getsockopt(sock, level, optname, optval, optlen) sceNetInetGetsockopt(sock, level, optname, optval, optlen)

int clock_gettime(clockid_t clockid, struct timespec *ts){
	uint64_t now = sceKernelGetSystemTimeWide();
	ts->tv_sec = now / 1000000;
	ts->tv_nsec = (now % 1000000) * 1000;
	return 0;
}
time_t time(time_t *out){
	time_t ret = sceKernelGetSystemTimeWide() / 1000000;
	if (out != NULL){
		*out = ret;
	}
	return ret;
}

// this assumes that the thread does not get interrupted, not a great way to do this
// this relies on how pspdev/psp/include/sys/errno.h works currently
int errno_array[10] = {0};
int *__errno(){
	static int idx = 0;
	idx++;
	if (idx == ARRAY_SIZE(errno_array)){
		idx = 0;
	}
	errno_array[idx] = sceNetInetGetErrno();
	return &errno_array[idx];
}

void abort(){
	LOG("%s: abort called on addr %p...\n", __func__, __builtin_return_address(0));
	_sw(0, 0);
}

char *strncpy(char *dest, const char *src, size_t count){
	for(int i = 0;i < count;i++){
		dest[i] = src[i];
		if (dest[i] == '\0'){
			break;
		}
	}
	return dest;
}

// gcc function
uint8_t __atomic_load_8(uint8_t *ptr, int memorder){
	int intr = sceKernelCpuSuspendIntr();
	uint8_t val = ptr[0];
	sceKernelCpuResumeIntr(intr);
	return val;
}

// gcc function
bool __atomic_compare_exchange_8(uint8_t *ptr, uint8_t *expected, uint8_t desired, bool weak, int success_memorder, int failure_memorder){
	int intr = sceKernelCpuSuspendIntr();
	bool ret = false;
	if (ptr[0] == expected[0]){
		ptr[0] = desired;
		ret = true;
	} else {
		expected[0] = ptr[0];
	}
	sceKernelCpuResumeIntr(intr);
	return ret;
}



#endif
