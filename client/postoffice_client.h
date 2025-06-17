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
	AEMU_POSTOFFICE_CLIENT_SESSION_DATA_TRUNC = -5
};

void *pdp_create_v6(struct in6_addr addr, int port, const char *pdp_mac, int pdp_port);
void *pdp_create_v4(struct in_addr addr, int port, const char *pdp_mac, int pdp_port);
void pdp_delete(void *pdp_handle);
int pdp_send(void *pdp_handle, const char *pdp_mac, int pdp_port, const char *buf, int len, bool non_block);
int pdp_recv(void *pdp_handle, char *pdp_mac, int *pdp_port, char *buf, int *len, bool non_block);

#endif
