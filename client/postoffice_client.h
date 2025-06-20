#ifndef __POSTOFFICE_CLIENT_H
#define __POSTOFFICE_CLIENT_H

#include <netinet/in.h>
#include <stdbool.h>

enum aemu_postoffice_client_errors {
	AEMU_POSTOFFICE_CLIENT_OK = 0,
	AEMU_POSTOFFICE_CLIENT_UNKNOWN = -1,
	AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY = -2,
	AEMU_POSTOFFICE_CLIENT_SESSION_DEAD = -3,
	AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK = -4,
	AEMU_POSTOFFICE_CLIENT_SESSION_DATA_TRUNC = -5,
	AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK = -6
};

void *pdp_create_v6(struct in6_addr addr, int port, const char *pdp_mac, int pdp_port, int *state);
void *pdp_create_v4(struct in_addr addr, int port, const char *pdp_mac, int pdp_port, int *state);
void pdp_delete(void *pdp_handle);
int pdp_send(void *pdp_handle, const char *pdp_mac, int pdp_port, const char *buf, int len, bool non_block);
int pdp_recv(void *pdp_handle, char *pdp_mac, int *pdp_port, char *buf, int *len, bool non_block);
void *ptp_listen_v6(struct in6_addr addr, int port, const char *ptp_mac, int ptp_port, int *state);
void *ptp_listen_v4(struct in_addr addr, int port, const char *ptp_mac, int ptp_port, int *state);
void *ptp_accept(void *ptp_listen_handle, bool nonblock, int *state);
void *ptp_connect_v6(struct in6_addr addr, int port, const char *src_ptp_mac, int ptp_sport, const char *dst_ptp_mac, int ptp_dport, int *state);
void *ptp_connect_v4(struct in_addr addr, int port, const char *src_ptp_mac, int ptp_sport, const char *dst_ptp_mac, int ptp_dport, int *state);
int ptp_send(void *ptp_handle, const char *buf, int len, bool non_block);
int ptp_recv(void *ptp_handle, char *buf, int *len, bool non_block);
void ptp_close(void *ptp_handle);
void ptp_listen_close(void *ptp_listen_handle);


#endif
