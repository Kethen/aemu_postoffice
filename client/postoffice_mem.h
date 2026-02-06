#ifndef __POSTOFFICE_MEM_H
#define __POSTOFFICE_MEM_H

#include <stdint.h>
#include "sock_impl.h"

#define PDP_BLOCK_MAX (10 * 1024)
#define PTP_BLOCK_MAX (50 * 1024)

struct pdp_session{
	char *pdp_mac[6];
	int16_t pdp_port;
	int sock;
	bool dead;
	bool abort;
	char recv_buf[PDP_BLOCK_MAX];
	bool recving;
	bool sending;
};

struct ptp_listen_session{
	char *ptp_mac[6];
	int16_t ptp_port;
	int sock;
	bool dead;
	bool abort;
	char addr[sizeof(native_sock6_addr) > sizeof(native_sock_addr) ? sizeof(native_sock6_addr) : sizeof(native_sock_addr)];
	int addrlen;
	bool accepting;
};

struct ptp_session{
	int sock;
	bool dead;
	bool abort;
	char recv_buf[PTP_BLOCK_MAX];
	int outstanding_data_size;
	int outstanding_data_offset;
	bool recving;
	bool sending;
};

extern int NUM_PDP_SESSIONS;
extern int NUM_PTP_LISTEN_SESSIONS;
extern int NUM_PTP_SESSIONS;

extern struct pdp_session *pdp_sessions;
extern struct ptp_listen_session *ptp_listen_sessions;
extern struct ptp_session *ptp_sessions;

void init_postoffice_mem();

#endif
