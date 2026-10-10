#ifndef __POSTOFFICE_CLIENT_H
#define __POSTOFFICE_CLIENT_H

#include <stdbool.h>
#include <stdint.h>

// current limits on send/recv calls
#define AEMU_POSTOFFICE_PDP_BLOCK_MAX (10 * 1024)
#define AEMU_POSTOFFICE_PTP_BLOCK_MAX (50 * 1024)

enum aemu_postoffice_client_errors {
	AEMU_POSTOFFICE_CLIENT_OK = 0,
	AEMU_POSTOFFICE_CLIENT_UNKNOWN = -1,
	AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY = -2,
	AEMU_POSTOFFICE_CLIENT_SESSION_DEAD = -3,
	AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK = -4,
	AEMU_POSTOFFICE_CLIENT_SESSION_DATA_TRUNC = -5,
	AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK = -6
};

struct aemu_postoffice_sock_addr{
	uint32_t addr; // network order
	uint16_t port; // network order
};

struct aemu_postoffice_sock6_addr{
	uint8_t addr[16]; // network order
	uint16_t port; // network order
};

#ifdef __cplusplus
extern "C" {
#endif

int init_aemu_postoffice(bool with_enet); // returns 0 on success, -1 on error
int pump_enet_aemu_postoffice(); // returns 0 on success, -1 on error, this has to be called frequently to facilitate enet functionalities
void deinit_aemu_postoffice();

/*
 * Thread safety:
 * multiple threads can perform create/listen/connect
 * only one thread at a time can accept on a created socket
 * only one thread at a time can send on a created socket
 * only one thread at a time can recv/peek on a created socket
 * only one thread at a time can close a created socket
 * aemu_postoffice_pump_enet can be called anytime
 *
 * violating the above yields undefined results
 */

void *pdp_create_v6(const struct aemu_postoffice_sock6_addr *addr, const char *pdp_mac, int pdp_port, bool enet, bool enet_reliable, int *state); // state is AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY when there is no slot anymore, 0 on success
void *pdp_create_v4(const struct aemu_postoffice_sock_addr *addr, const char *pdp_mac, int pdp_port, bool enet, bool enet_reliable, int *state); // state is AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY when there is no slot anymore, 0 on success
void pdp_delete(void *pdp_handle);
int pdp_send(void *pdp_handle, const char *pdp_mac, int pdp_port, const char *buf, int len, bool non_block); // returns 0 on success, AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK when there is not currently buffer space for send queuing, and other < 0 results on other errors
int pdp_recv(void *pdp_handle, char *pdp_mac, int *pdp_port, char *buf, int *len, bool non_block); // returns 0 on success, AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK when there is no data to be received, AEMU_POSTOFFICE_CLIENT_SESSION_DATA_TRUNC when recv buffer is too small to receive the packet, other < 0 results on other errors
int pdp_peek_next_size(void *pdp_handle); // returns size required for the next pdp packet, 0 when there is no packet, other < 0 results on other errors
int pdp_buffered_data_size(void *pdp_handle); // returns total amount of buffered data that can be received without returning AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK, other < 0 results on other errors
int pdp_send_buf_not_full(void *pdp_handle); // returns 1 when send buffer is not full, returns 0 when send buffer is full, AEMU_POSTOFFICE_CLIENT_SESSION_DEAD when a session is disconnected
bool pdp_is_dead(void *ptp_handle);
void *ptp_listen_v6(const struct aemu_postoffice_sock6_addr *addr, const char *ptp_mac, int ptp_port, bool enet, int *state); // state is AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY when there is no slot anymore, 0 on success
void *ptp_listen_v4(const struct aemu_postoffice_sock_addr *addr, const char *ptp_mac, int ptp_port, bool enet, int *state); // state is AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY when there is no slot anymore, 0 on success
void *ptp_accept(void *ptp_listen_handle, char *ptp_mac, int *ptp_port, bool nonblock, int *state); // state is AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY when there is no slot anymore, AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK when there are no incoming connections, 0 on success
void *ptp_connect_v6(const struct aemu_postoffice_sock6_addr *addr, const char *src_ptp_mac, int ptp_sport, const char *dst_ptp_mac, int ptp_dport, bool enet, int *state); // state is AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY when there is no slot anymore, 0 on success, other < 0 results on other errors
void *ptp_connect_v4(const struct aemu_postoffice_sock_addr *addr, const char *src_ptp_mac, int ptp_sport, const char *dst_ptp_mac, int ptp_dport, bool enet, int *state); // state is AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY when there is no slot anymore, 0 on success, other < 0 results on other errors
int ptp_send(void *ptp_handle, const char *buf, int len, bool non_block); // returns 0 on success, AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK when there is not currently buffer space for send queuing, and other < 0 results on other errors
int ptp_recv(void *ptp_handle, char *buf, int *len, bool non_block); // returns 0 on success, AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK when there is no data to be received, other < 0 results on other errors
void ptp_close(void *ptp_handle);
void ptp_listen_close(void *ptp_listen_handle);
int ptp_peek_next_size(void *ptp_handle); // returns size of buffered data that can be received without returning AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK
int ptp_send_buf_not_full(void *pdp_handle); // returns 1 when send buffer is not full, returns 0 when send buffer is full, AEMU_POSTOFFICE_CLIENT_SESSION_DEAD when a session is disconnected
int ptp_listen_has_request(void *pdp_listen_handler); // returns 1 when ptp_accept can be called without returning AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK, 0 when there is no incoming connection, < 0 for other errors
bool ptp_is_dead(void *ptp_handle);
bool ptp_listen_is_dead(void *ptp_listen_handle);

#ifdef __cplusplus
}
#endif

#endif
