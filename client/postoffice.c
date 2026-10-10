#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "postoffice_client.h"

#include "log_impl.h"
#include "sock_impl.h"
#include "enet.h"
#include "mutex_impl.h"
#include "delay_impl.h"
#include "postoffice_mem.h"

#include "../aemu_postoffice_packets.h"

static bool initialized = false;

int init_aemu_postoffice(bool with_enet){
	if (initialized){
		return 0;
	}

	if (with_enet){
		if (init_enet() != 0){
			return -1;
		}
	}
	init_postoffice_mem();
	init_mutex();

	for (int i = 0;i < NUM_PDP_SESSIONS;i++){
		pdp_sessions[i].sock = -1;
	}
	for (int i = 0;i < NUM_PTP_LISTEN_SESSIONS;i++){
		ptp_listen_sessions[i].sock = -1;
	}
	for (int i = 0;i < NUM_PTP_SESSIONS;i++){
		ptp_sessions[i].sock = -1;
	}

	initialized = true;
	return 0;
}

int pump_enet_aemu_postoffice(){
	pump_enet();
}

void deinit_aemu_postoffice(){
	if (!initialized){
		return;
	}

	for (int i = 0;i < NUM_PDP_SESSIONS;i++){
		if (pdp_sessions[i].sock != -1){
			pdp_delete(&pdp_sessions[i]);
		}
	}
	for (int i = 0;i < NUM_PTP_LISTEN_SESSIONS;i++){
		if (ptp_listen_sessions[i].sock != -1){
			ptp_listen_close(&ptp_listen_sessions[i]);
		}
	}
	for (int i = 0;i < NUM_PTP_SESSIONS;i++){
		if (ptp_sessions[i].sock != -1){
			ptp_close(&ptp_sessions[i]);
		}
	}

	deinit_enet();
	deinit_postoffice_mem();
	deinit_mutex();

	initialized = false;
}

static int send_wrapped(int sock, void *enet_handle, bool enet_reliable, const char *buf, int len){
	if (enet_handle == NULL){
		return native_send(sock, buf, len);
	}

	return send_enet(enet_handle, buf, len, 0, enet_reliable);
}

static int recv_wrapped(int sock, void *enet_handle, char *buf, int len){
	if (enet_handle == NULL){
		return native_recv(sock, buf, len);
	}

	return recv_enet(enet_handle, buf, len, 0);
}

static int peek_wrapped(int sock, void *enet_handle, char *buf, int len){
	if (enet_handle == NULL){
		return native_peek(sock, buf, len);
	}
	return peek_enet(enet_handle, buf, len, 0);
}

static bool send_buf_not_full_wrapped(int sock, void *enet_handle){
	if (enet_handle == NULL){
		return native_send_buf_not_full(sock);
	}
	// TODO not sure what to do on enet yet, perhaps to check if there is free heap
	// when it is figured out, implement it into enet.cpp
	return true;
}

static bool hung_up_wrapped(int sock, void *enet_handle){
	if (enet_handle == NULL){
		return native_hung_up(sock);
	}
	return is_disconnected_enet(enet_handle);
}

static bool connect_wrapped(const struct aemu_postoffice_sock_addr *addr4, const struct aemu_postoffice_sock6_addr *addr6, bool enet, int *sock, void **enet_handle, const char *caller_name){
	if (!enet){
		enet_handle[0] = NULL;
		sock[0] = native_connect_tcp_sock(addr4, addr6);
		if (sock[0] < 0){
			LOG("%s: tcp connection failed\n", caller_name);
			return false;
		}
	} else {
		sock[0] = 0;
		enet_handle[0] = connect_enet(addr4, addr6, 1);
		if (enet_handle[0] == NULL){
			LOG("%s: enet connection failed\n", caller_name);
			return false;
		}
	}
	return true;
}

static void close_wrapped(int sock, void *enet_handle){
	if (enet_handle == NULL){
		native_close_tcp_sock(sock);
		return;
	}
	close_enet(enet_handle);
}

#define ABORTED -100

static int send_till_done(int fd, void *enet_handle, bool enet_reliable, const char *buf, int len, bool non_block, bool *abort){
	int write_offset = 0;
	while(write_offset != len){
		if (*abort){
			return ABORTED;
		}
		int write_status = send_wrapped(fd, enet_handle, enet_reliable, &buf[write_offset], len - write_offset);
		if (write_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
			if (non_block && write_offset == 0){
				delay(0);
				return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
			}
			delay(0);
			continue;
		}
		if (write_status == -1){
			return write_status;
		}
		write_offset += write_status;
	}
	return write_offset;
}

static int recv_till_done(int fd, void *enet_handle, char *buf, int len, bool non_block, bool *abort){
	int read_offset = 0;
	while(read_offset != len){
		if (*abort){
			return ABORTED;
		}
		int recv_status = recv_wrapped(fd, enet_handle, &buf[read_offset], len - read_offset);
		if (recv_status == 0){
			return recv_status;
		}
		if (recv_status < 0){
			if (recv_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
				if (non_block && read_offset == 0){
					delay(0);
					return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
				}
				// Continue block receving, either in block mode or we already received part of the message
				delay(0);
				continue;
			}
			return recv_status;
		}
		read_offset += recv_status;
	}
	return read_offset;
}

static bool create_and_init_socket(const struct aemu_postoffice_sock_addr *addr4, const struct aemu_postoffice_sock6_addr *addr6, bool enet, const char *init_packet, int init_packet_len, const char *caller_name, int *sock, void **enet_handle){
	if (!connect_wrapped(addr4, addr6, enet, sock, enet_handle, caller_name)){
		LOG("%s: failed connecting to server\n", caller_name);
		return false;
	}

	bool abort = false;
	int write_status = send_till_done(sock[0], enet_handle[0], true, (char *)init_packet, init_packet_len, false, &abort);
	if (write_status == -1){
		LOG("%s: failed sending init packet\n", caller_name);
		close_wrapped(sock[0], enet_handle[0]);
		return false;
	}

	return sock;
}

static void *pdp_create(const struct aemu_postoffice_sock_addr *addr4, const struct aemu_postoffice_sock6_addr *addr6, const char *pdp_mac, int pdp_port, bool enet, bool enet_reliable, int *state){
	struct pdp_session* session = NULL;
	lock_sock_alloc_mutex();
	for(int i = 0;i < NUM_PDP_SESSIONS;i++){
		if (pdp_sessions[i].sock == -1){
			session = &pdp_sessions[i];
			session->sock = 0;
			break;
		}
	}
	unlock_sock_alloc_mutex();
	if (session == NULL){
		LOG("%s: failed allocating memory for pdp session\n", __func__);
		*state = AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY;
		return NULL;
	}

	// Prepare init packet
	struct aemu_postoffice_init init_packet = {0};
	init_packet.init_type = AEMU_POSTOFFICE_INIT_PDP;
	memcpy(init_packet.src_addr, pdp_mac, 6);
	init_packet.sport = pdp_port;
	if (enet && !enet_reliable){
		init_packet.init_type = AEMU_POSTOFFICE_INIT_PDP_UNRELIABLE;
	}

	bool created = create_and_init_socket(addr4, addr6, enet, (char *)&init_packet, sizeof(init_packet), __func__, &session->sock, &session->enet_handle);

	if (!created){
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		session->sock = -1;
		return NULL;
	}

	memcpy(session->pdp_mac, pdp_mac, 6);
	session->pdp_port = pdp_port;
	session->dead = false;
	session->abort = false;
	session->recving = false;
	session->sending = false;
	session->recv_ring_buf_start = 0;
	session->recv_ring_buf_used = 0;
	session->buffered_data = 0;
	session->bytes_till_next_header = 0;
	session->last_block_size = 0;
	session->enet_reliable = enet_reliable;

	*state = AEMU_POSTOFFICE_CLIENT_OK;
	return session;
}

void *pdp_create_v6(const struct aemu_postoffice_sock6_addr *addr, const char *pdp_mac, int pdp_port, bool enet, bool enet_reliable, int *state){
	return pdp_create(NULL, addr, pdp_mac, pdp_port, enet, enet_reliable, state);
}

void *pdp_create_v4(const struct aemu_postoffice_sock_addr *addr, const char *pdp_mac, int pdp_port, bool enet, bool enet_reliable, int *state){
	return pdp_create(addr, NULL, pdp_mac, pdp_port, enet, enet_reliable, state);
}

int pdp_send(void *pdp_handle, const char *pdp_mac, int pdp_port, const char *buf, int len, bool non_block){
	if (pdp_handle == NULL){
		return -1;
	}
	struct pdp_session *session = (struct pdp_session *)pdp_handle;
	if (session->dead || session->abort){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (len > AEMU_POSTOFFICE_PDP_BLOCK_MAX){
		LOG("%s: failed sending data, data too big, %d\n", __func__, len);
		return AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY;
	}

	// Write header
	struct aemu_postoffice_pdp pdp_header = {
		.port = pdp_port,
		.size = len
	};
	memcpy(pdp_header.addr, pdp_mac, 6);

	session->sending = true;
	int send_status = send_till_done(session->sock, session->enet_handle, session->enet_reliable, (char *)&pdp_header, sizeof(pdp_header), non_block, &session->abort);
	session->sending = false;
	if (send_status == ABORTED){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}
	if (send_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	if (send_status < 0){
		// Error
		LOG("%s: failed sending header\n", __func__);
		session->dead = true;
		close_wrapped(session->sock, session->enet_handle);
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	session->sending = true;
	send_status = send_till_done(session->sock, session->enet_handle, session->enet_reliable, buf, len, false, &session->abort);
	session->sending = false;
	if (send_status == ABORTED){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (send_status < 0){
		// Error
		LOG("%s: failed sending data\n", __func__);
		session->dead = true;
		close_wrapped(session->sock, session->enet_handle);
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	return AEMU_POSTOFFICE_CLIENT_OK;
}

static int peek_ring_buf(uint8_t *dst, int dst_size, const uint8_t *ring_buf, int ring_buf_size, int ring_buf_begin, int ring_buf_used){
	int to_peek = dst_size > ring_buf_used ? ring_buf_used : dst_size;
	for (int i = 0;i < to_peek;i++){
		int ring_buf_offset = (ring_buf_begin + i) % ring_buf_size;
		dst[i] = ring_buf[ring_buf_offset];
	}
	return to_peek;
}

static int consume_ring_buf(uint8_t *dst, int dst_size, const uint8_t *ring_buf, int ring_buf_size, int *ring_buf_begin, int *ring_buf_used){
	int peeked = peek_ring_buf(dst, dst_size, ring_buf, ring_buf_size, *ring_buf_begin, *ring_buf_used);
	*ring_buf_begin = (*ring_buf_begin + peeked) % ring_buf_size;
	*ring_buf_used = *ring_buf_used - peeked;
	return peeked;
}

static int pdp_drain_blocks_to_ring_buf(struct pdp_session *session){
	while (true){
		int ring_buf_free = sizeof(session->recv_ring_buf) - session->recv_ring_buf_used;
		if (session->bytes_till_next_header == 0){
			if (session->last_block_size != 0){
				session->buffered_data = session->buffered_data + session->last_block_size;
				session->last_block_size = 0;
			}
			if (ring_buf_free < sizeof(aemu_postoffice_pdp)){
				return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
			}

			aemu_postoffice_pdp header;
			int peek_len = peek_wrapped(session->sock, session->enet_handle, (char *)&header, sizeof(header));
			if (peek_len == 0){
				LOG("%s: remote closed the socket\n", __func__);
				close_wrapped(session->sock, session->enet_handle);
				session->dead = true;
				return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
			}
			if (peek_len == -1){
				LOG("%s: failed peeking header\n", __func__);
				close_wrapped(session->sock, session->enet_handle);
				session->dead = true;
				return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
			}
			if (peek_len != sizeof(header)){
				return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
			}

			int recv_status = recv_wrapped(session->sock, session->enet_handle, (char *)&header, sizeof(header));
			if (recv_status == 0){
				LOG("%s: remote closed the socket\n", __func__);
				close_wrapped(session->sock, session->enet_handle);
				session->dead = true;
				return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
			}
			if (recv_status == -1){
				LOG("%s: failed receiving header\n", __func__);
				close_wrapped(session->sock, session->enet_handle);
				session->dead = true;
				return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
			}
			if (header.size > AEMU_POSTOFFICE_PDP_BLOCK_MAX){
				LOG("%s: remote sent unexpected amount of data\n", __func__);
				close_wrapped(session->sock, session->enet_handle);
				session->dead = true;
				return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
			}

			session->bytes_till_next_header = header.size;
			session->last_block_size = header.size;
			uint8_t *header_bytes = (uint8_t *)&header;
			int ring_buf_end = (session->recv_ring_buf_start + session->recv_ring_buf_used) % sizeof(session->recv_ring_buf);
			for (int i = 0;i < sizeof(header);i++){
				int ring_buf_offset = (ring_buf_end + i) % sizeof(session->recv_ring_buf);
				session->recv_ring_buf[ring_buf_offset] = header_bytes[i];
			}
			session->recv_ring_buf_used = session->recv_ring_buf_used + sizeof(header);
			continue;
		}

		int ring_buf_end = (session->recv_ring_buf_start + session->recv_ring_buf_used) % sizeof(session->recv_ring_buf);
		int linear_size_from_end = sizeof(session->recv_ring_buf) - ring_buf_end;
		int to_consume = ring_buf_free;
		if (to_consume > linear_size_from_end){
			to_consume = linear_size_from_end;
		}
		if (to_consume > session->bytes_till_next_header){
			to_consume = session->bytes_till_next_header;
		}

		if (to_consume == 0){
			return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
		}

		int recv_status = recv_wrapped(session->sock, session->enet_handle, &session->recv_ring_buf[ring_buf_end], to_consume);
		if (recv_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
			return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
		}
		if (recv_status == 0){
			LOG("%s: remote closed the socket\n", __func__);
			close_wrapped(session->sock, session->enet_handle);
			session->dead = true;
			return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		}
		if (recv_status == -1){
			LOG("%s: failed receiving data\n", __func__);
			close_wrapped(session->sock, session->enet_handle);
			session->dead = true;
			return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		}
		session->recv_ring_buf_used = session->recv_ring_buf_used + recv_status;
		session->bytes_till_next_header = session->bytes_till_next_header - recv_status;
	}
}

static int pdp_drain_blocks_to_ring_buf_locked(struct pdp_session *session){
	session->recving = true;
	lock_drain_mutex();
	int result = pdp_drain_blocks_to_ring_buf(session);
	unlock_drain_mutex();
	session->recving = false;
	return result;
}

int pdp_recv(void *pdp_handle, char *pdp_mac, int *pdp_port, char *buf, int *len, bool non_block){
	if (pdp_handle == NULL){
		return -1;
	}
	struct pdp_session *session = (struct pdp_session *)pdp_handle;
	if (session->dead || session->abort){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	while (true){
		if (session->abort){
			return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		}
		int drain_result = pdp_drain_blocks_to_ring_buf_locked(session);
		if (drain_result == AEMU_POSTOFFICE_CLIENT_SESSION_DEAD){
			return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		}
		// AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK

		aemu_postoffice_pdp header;
		int peeked = peek_ring_buf((uint8_t *)&header, sizeof(header), (uint8_t *)session->recv_ring_buf, sizeof(session->recv_ring_buf), session->recv_ring_buf_start, session->recv_ring_buf_used);
		if (peeked != sizeof(header)){
			if (non_block){
				return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
			}else{
				// yield so that on the PSP new data can get into the recv buffer
				delay(0);
				continue;
			}
		}

		int total_size = sizeof(header) + header.size;
		if (total_size > session->recv_ring_buf_used){
			if (non_block){
				return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
			}else{
				// yield so that on the PSP new data can get into the recv buffer
				delay(0);
				continue;
			}
		}

		break;
	}

	aemu_postoffice_pdp header;
	peek_ring_buf((uint8_t *)&header, sizeof(header), (uint8_t *)session->recv_ring_buf, sizeof(session->recv_ring_buf), session->recv_ring_buf_start, session->recv_ring_buf_used);
	*pdp_port = header.port;
	memcpy(pdp_mac, header.addr, 6);
	if (header.size > *len){
		*len = header.size;
		return AEMU_POSTOFFICE_CLIENT_SESSION_DATA_TRUNC;
	}
	consume_ring_buf((uint8_t *)&header, sizeof(header), (uint8_t *)session->recv_ring_buf, sizeof(session->recv_ring_buf), &session->recv_ring_buf_start, &session->recv_ring_buf_used);
	consume_ring_buf((uint8_t *)buf, header.size, (uint8_t *)session->recv_ring_buf, sizeof(session->recv_ring_buf), &session->recv_ring_buf_start, &session->recv_ring_buf_used);
	session->buffered_data = session->buffered_data - header.size;
	*len = header.size;

	return AEMU_POSTOFFICE_CLIENT_OK;
}

void pdp_delete(void *pdp_handle){
	if (pdp_handle == NULL){
		return;
	}
	struct pdp_session *session = (struct pdp_session *)pdp_handle;

	// abort on-going ops
	session->abort = true;

	// make sure we are clear of send/recv operations
	do{
		delay(50);
	}while(session->sending || session->recving);

	if (!session->dead)
		close_wrapped(session->sock, session->enet_handle);
	session->sock = -1;
}

int pdp_peek_next_size(void *pdp_handle){
	struct pdp_session *session = pdp_handle;

	if (session->dead || session->abort){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	int drain_result = pdp_drain_blocks_to_ring_buf_locked(session);
	if (drain_result == AEMU_POSTOFFICE_CLIENT_SESSION_DEAD){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (session->recv_ring_buf_used < sizeof(aemu_postoffice_pdp)){
		return 0;
	}

	aemu_postoffice_pdp header;
	peek_ring_buf((uint8_t *)&header, sizeof(header), (uint8_t *)session->recv_ring_buf, sizeof(session->recv_ring_buf), session->recv_ring_buf_start, session->recv_ring_buf_used);
	if (session->buffered_data >= header.size){
		return header.size;
	}
	return 0;
}

int pdp_buffered_data_size(void *pdp_handle){
	struct pdp_session *session = pdp_handle;

	if (session->dead || session->abort){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	int drain_result = pdp_drain_blocks_to_ring_buf_locked(session);
	if (drain_result == AEMU_POSTOFFICE_CLIENT_SESSION_DEAD){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	return session->buffered_data;
}

bool pdp_is_dead(void *pdp_handle){
	if (pdp_handle == NULL){
		return true;
	}

	struct pdp_session *session = (struct pdp_session *)pdp_handle;
	if (session->dead || session->abort){
		return true;
	}

	if (hung_up_wrapped(session->sock, session->enet_handle)){
		LOG("%s: the other side closed the listen socket\n", __func__);
		session->dead = true;
		close_wrapped(session->sock, session->enet_handle);
		return true;
	}

	return false;
}

int pdp_send_buf_not_full(void *pdp_handle){
	if (pdp_is_dead(pdp_handle)){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	struct pdp_session *session = pdp_handle;

	return send_buf_not_full_wrapped(session->sock, session->enet_handle);
}

static void *ptp_listen(const struct aemu_postoffice_sock_addr *addr4, const struct aemu_postoffice_sock6_addr *addr6, const char *ptp_mac, int ptp_port, bool enet, int *state){
	struct ptp_listen_session* session = NULL;
	lock_sock_alloc_mutex();
	for(int i = 0;i < NUM_PTP_LISTEN_SESSIONS;i++){
		if (ptp_listen_sessions[i].sock == -1){
			session = &ptp_listen_sessions[i];
			session->sock = 0;
			break;
		}
	}
	unlock_sock_alloc_mutex();
	if (session == NULL){
		LOG("%s: failed allocating memory for ptp listen session\n", __func__);
		*state = AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY;
		return NULL;
	}

	// Prepare init packet
	struct aemu_postoffice_init init_packet = {0};
	init_packet.init_type = AEMU_POSTOFFICE_INIT_PTP_LISTEN;
	memcpy(init_packet.src_addr, ptp_mac, 6);
	init_packet.sport = ptp_port;

	bool created = create_and_init_socket(addr4, addr6, enet, (char *)&init_packet, sizeof(init_packet), __func__, &session->sock, &session->enet_handle);

	if (!created){
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		session->sock = -1;
		return NULL;
	}

	memcpy(session->ptp_mac, ptp_mac, 6);
	session->ptp_port = ptp_port;
	session->dead = false;
	session->abort = false;
	session->accepting = false;
	if (addr4 != NULL){
		session->addr4 = addr4[0];
		session->is_addr6 = false;
	} else {
		session->addr6 = addr6[0];
		session->is_addr6 = true;
	}

	*state = AEMU_POSTOFFICE_CLIENT_OK;
	return session;
}

void *ptp_listen_v6(const struct aemu_postoffice_sock6_addr *addr, const char *ptp_mac, int ptp_port, bool enet, int *state){
	return ptp_listen(NULL, addr, ptp_mac, ptp_port, enet, state);
}

void *ptp_listen_v4(const struct aemu_postoffice_sock_addr *addr, const char *ptp_mac, int ptp_port, bool enet, int *state){
	return ptp_listen(addr, NULL, ptp_mac, ptp_port, enet, state);
}

void *ptp_accept(void *ptp_listen_handle, char *ptp_mac, int *ptp_port, bool nonblock, int *state){
	if (ptp_listen_handle == NULL){
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		return NULL;
	}

	struct ptp_listen_session *session = (struct ptp_listen_session *)ptp_listen_handle;
	if (session->dead){
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		return NULL;
	}

	struct aemu_postoffice_ptp_connect connect_packet;
	session->accepting = true;
	int recv_status = recv_till_done(session->sock, session->enet_handle, (char *)&connect_packet, sizeof(connect_packet), nonblock, &session->abort);
	session->accepting = false;
	if (recv_status == ABORTED){
		// getting aborted
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		return NULL;
	}
	if (recv_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
		return NULL;
	}
	if (recv_status == 0){
		LOG("%s: the other side closed the listen socket\n", __func__);
		session->dead = true;
		close_wrapped(session->sock, session->enet_handle);
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		return NULL;
	}
	if (recv_status <= 0){
		LOG("%s: socket error, %d\n", __func__, recv_status);
		session->dead = true;
		close_wrapped(session->sock, session->enet_handle);
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		return NULL;
	}

	// Allocate memory
	struct ptp_session *new_session = NULL;
	lock_sock_alloc_mutex();
	for(int i = 0;i < NUM_PTP_SESSIONS;i++){
		if (ptp_sessions[i].sock == -1){
			new_session = &ptp_sessions[i];
			new_session->sock = 0;
			break;
		}
	}
	unlock_sock_alloc_mutex();
	if (new_session == NULL){
		*state = AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY;
		return NULL;
	}

	// Prepare init packet
	struct aemu_postoffice_init init_packet;
	init_packet.init_type = AEMU_POSTOFFICE_INIT_PTP_ACCEPT;
	memcpy(init_packet.src_addr, session->ptp_mac, 6);
	init_packet.sport = session->ptp_port;
	memcpy(init_packet.dst_addr, connect_packet.addr, 6);
	init_packet.dport = connect_packet.port;

	bool created = false;
	if (session->is_addr6){
		created = create_and_init_socket(NULL, &session->addr6, session->enet_handle != NULL, (char *)&init_packet, sizeof(init_packet), __func__, &new_session->sock, &new_session->enet_handle);
	} else {
		created = create_and_init_socket(&session->addr4, NULL, session->enet_handle != NULL, (char *)&init_packet, sizeof(init_packet), __func__, &new_session->sock, &new_session->enet_handle);
	}

	if (!created){
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		new_session->sock = -1;
		return NULL;
	}

	// Consume the ack packet
	bool abort = false;
	int read_status = recv_till_done(new_session->sock, new_session->enet_handle, (char *)&connect_packet, sizeof(connect_packet), false, &abort);
	if (read_status == 0){
		LOG("%s: remote closed the socket during initial recv\n", __func__);
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		close_wrapped(new_session->sock, new_session->enet_handle);
		new_session->sock = -1;
		return NULL;
	}
	if (read_status == -1){
		LOG("%s: socket error receiving initial packet\n", __func__);
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		close_wrapped(new_session->sock, new_session->enet_handle);
		new_session->sock = -1;
		return NULL;
	}

	// Now the session is ready
	new_session->dead = false;
	new_session->abort = false;
	new_session->sending = false;
	new_session->recving = false;
	new_session->recv_ring_buf_start = 0;
	new_session->recv_ring_buf_used = 0;
	new_session->bytes_till_next_header = 0;
	*state = AEMU_POSTOFFICE_CLIENT_OK;
	*ptp_port = connect_packet.port;
	memcpy(ptp_mac, connect_packet.addr, 6);
	return new_session;
}

static void *ptp_connect(const struct aemu_postoffice_sock_addr *addr4, const struct aemu_postoffice_sock6_addr *addr6, const char *src_ptp_mac, int ptp_sport, const char *dst_ptp_mac, int ptp_dport, bool enet, int *state){
	// Allocate memory
	struct ptp_session *new_session = NULL;
	lock_sock_alloc_mutex();
	for(int i = 0;i < NUM_PTP_SESSIONS;i++){
		if (ptp_sessions[i].sock == -1){
			new_session = &ptp_sessions[i];
			new_session->sock = 0;
			break;
		}
	}
	unlock_sock_alloc_mutex();
	if (new_session == NULL){
		*state = AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY;
		return NULL;
	}

	// Prepare init packet
	struct aemu_postoffice_init init_packet;
	init_packet.init_type = AEMU_POSTOFFICE_INIT_PTP_CONNECT;
	memcpy(init_packet.src_addr, src_ptp_mac, 6);
	init_packet.sport = ptp_sport;
	memcpy(init_packet.dst_addr, dst_ptp_mac, 6);
	init_packet.dport = ptp_dport;

	bool created = create_and_init_socket(addr4, addr6, enet, (char *)&init_packet, sizeof(init_packet), __func__, &new_session->sock, &new_session->enet_handle);

	if (!created){
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		new_session->sock = -1;
		return NULL;
	}

	// Consume the ack packet
	struct aemu_postoffice_ptp_connect connect_packet;
	bool abort = false;
	int read_status = recv_till_done(new_session->sock, new_session->enet_handle, (char *)&connect_packet, sizeof(connect_packet), false, &abort);
	if (read_status == 0){
		LOG("%s: remote closed the socket during initial recv\n", __func__);
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		close_wrapped(new_session->sock, new_session->enet_handle);
		new_session->sock = -1;
		return NULL;
	}
	if (read_status == -1){
		LOG("%s: socket error receiving initial packet\n", __func__);
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		close_wrapped(new_session->sock, new_session->enet_handle);
		new_session->sock = -1;
		return NULL;
	}

	// Now the session is ready
	new_session->dead = false;
	new_session->abort = false;
	new_session->sending = false;
	new_session->recving = false;
	new_session->recv_ring_buf_start = 0;
	new_session->recv_ring_buf_used = 0;
	new_session->bytes_till_next_header = 0;
	*state = AEMU_POSTOFFICE_CLIENT_OK;
	return new_session;
}

void *ptp_connect_v6(const struct aemu_postoffice_sock6_addr *addr, const char *src_ptp_mac, int ptp_sport, const char *dst_ptp_mac, int ptp_dport, bool enet, int *state){
	return ptp_connect(NULL, addr, src_ptp_mac, ptp_sport, dst_ptp_mac, ptp_dport, enet, state);
}

void *ptp_connect_v4(const struct aemu_postoffice_sock_addr *addr, const char *src_ptp_mac, int ptp_sport, const char *dst_ptp_mac, int ptp_dport, bool enet, int *state){
	return ptp_connect(addr, NULL, src_ptp_mac, ptp_sport, dst_ptp_mac, ptp_dport, enet, state);
}

int ptp_send(void *ptp_handle, const char *buf, int len, bool non_block){
	if (ptp_handle == NULL){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	struct ptp_session *session = (struct ptp_session *)ptp_handle;
	if (session->dead || session->abort){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (len > AEMU_POSTOFFICE_PTP_BLOCK_MAX){
		LOG("%s: failed sending data, data too big, %d\n", __func__, len);
		return AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY;
	}

	struct aemu_postoffice_ptp_data header = {
		.size = len
	};

	session->sending = true;
	int send_status = send_till_done(session->sock, session->enet_handle, true, (char *)&header, sizeof(header), non_block, &session->abort);
	session->sending = false;
	if (send_status == ABORTED){
		// getting aborted
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}
	if (send_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	if (send_status < 0){
		LOG("%s: failed sending header\n", __func__);
		close_wrapped(session->sock, session->enet_handle);
		session->dead = true;
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	session->sending = true;
	send_status = send_till_done(session->sock, session->enet_handle, true, buf, len, false, &session->abort);
	session->sending = false;
	if (send_status == ABORTED){
		// getting aborted
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}
	if (send_status < 0){
		LOG("%s: failed sending data\n", __func__);
		close_wrapped(session->sock, session->enet_handle);
		session->dead = true;
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	return AEMU_POSTOFFICE_CLIENT_OK;
}

static int ptp_drain_blocks_to_ring_buf(struct ptp_session *session){
	while(true){
		if (session->bytes_till_next_header == 0){
			struct aemu_postoffice_ptp_data header = {0};
			int peek_result = peek_wrapped(session->sock, session->enet_handle, (char *)&header, sizeof(header));
			if (peek_result == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
				return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
			}
			if (peek_result == 0){
				LOG("%s: remote closed the socket\n", __func__);
				close_wrapped(session->sock, session->enet_handle);
				session->dead = true;
				return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
			}
			if (peek_result == -1){
				LOG("%s: failed peeking header\n", __func__);
				close_wrapped(session->sock, session->enet_handle);
				session->dead = true;
				return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
			}
			if (peek_result != sizeof(header)){
				return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
			}
			int recv_status = recv_wrapped(session->sock, session->enet_handle, (char *)&header, sizeof(header));
			if (recv_status == 0){
				LOG("%s: remote closed the socket\n", __func__);
				close_wrapped(session->sock, session->enet_handle);
				session->dead = true;
				return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
			}
			if (recv_status == -1){
				LOG("%s: failed reading header\n", __func__);
				close_wrapped(session->sock, session->enet_handle);
				session->dead = true;
				return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
			}

			if (header.size > AEMU_POSTOFFICE_PTP_BLOCK_MAX){
				LOG("%s: remote sent unexpected amount of data\n", __func__);
				close_wrapped(session->sock, session->enet_handle);
				session->dead = true;
				return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
			}

			session->bytes_till_next_header = header.size;
		}

		int ring_buf_free = sizeof(session->recv_ring_buf) - session->recv_ring_buf_used;
		int ring_buf_end = (session->recv_ring_buf_start + session->recv_ring_buf_used) % sizeof(session->recv_ring_buf);
		int linear_size_from_end = sizeof(session->recv_ring_buf) - ring_buf_end;
		int to_append = ring_buf_free;
		if (to_append > session->bytes_till_next_header){
			to_append = session->bytes_till_next_header;
		}
		if (to_append > linear_size_from_end){
			to_append = linear_size_from_end;
		}
		if (to_append == 0){
			return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
		}

		int recv_status = recv_wrapped(session->sock, session->enet_handle, &session->recv_ring_buf[ring_buf_end], to_append);
		if (recv_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
			return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
		}
		if (recv_status == 0){
			LOG("%s: remote closed the socket\n", __func__);
			close_wrapped(session->sock, session->enet_handle);
			session->dead = true;
			return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		}
		if (recv_status == -1){
			LOG("%s: failed reading data\n", __func__);
			close_wrapped(session->sock, session->enet_handle);
			session->dead = true;
			return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		}
		session->recv_ring_buf_used = session->recv_ring_buf_used + recv_status;
		session->bytes_till_next_header = session->bytes_till_next_header - recv_status;
	}
}

static int ptp_drain_blocks_to_ring_buf_locked(struct ptp_session *session){
	session->recving = true;
	lock_drain_mutex();
	int result = ptp_drain_blocks_to_ring_buf(session);
	unlock_drain_mutex();
	session->recving = false;
	return result;
}

int ptp_recv(void *ptp_handle, char *buf, int *len, bool non_block){
	if (ptp_handle == NULL){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	struct ptp_session *session = (struct ptp_session *)ptp_handle;
	if (session->dead || session->abort){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	while(true){
		if (session->abort){
			return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		}
		int drain_result = ptp_drain_blocks_to_ring_buf_locked(session);
		if (drain_result == AEMU_POSTOFFICE_CLIENT_SESSION_DEAD){
			return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		}
		if (drain_result == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
			if (non_block){
				break;
			}
			if (session->recv_ring_buf_used != 0){
				break;
			}
		}
		// yield so that on the PSP new data can get into the recv buffer
		delay(0);
	}

	if (session->recv_ring_buf_used == 0){
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	int ring_buffer_consumed = consume_ring_buf((uint8_t *)buf, *len, (uint8_t *)session->recv_ring_buf, sizeof(session->recv_ring_buf), &session->recv_ring_buf_start, &session->recv_ring_buf_used);
	*len = ring_buffer_consumed;

	return AEMU_POSTOFFICE_CLIENT_OK;
}

void ptp_close(void *ptp_handle){
	if (ptp_handle == NULL){
		return;
	}

	struct ptp_session *session = (struct ptp_session *)ptp_handle;

	// abort on-going ops
	session->abort = true;

	// make sure we are clear of send/recv operations
	do{
		delay(50);
	}while(session->sending || session->recving);

	if (!session->dead)
		close_wrapped(session->sock, session->enet_handle);
	session->sock = -1;
}

void ptp_listen_close(void *ptp_listen_handle){
	if (ptp_listen_handle == NULL){
		return;
	}

	struct ptp_listen_session *session = (struct ptp_listen_session *)ptp_listen_handle;

	// abort on-going ops
	session->abort = true;

	// make sure we are clear of send/recv operations
	do{
		delay(50);
	}while(session->accepting);

	if (!session->dead)
		close_wrapped(session->sock, session->enet_handle);
	session->sock = -1;
}

int ptp_peek_next_size(void *ptp_handle){
	struct ptp_session *session = ptp_handle;

	if (session->dead || session->abort){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	int drain_result = ptp_drain_blocks_to_ring_buf_locked(session);
	if (drain_result == AEMU_POSTOFFICE_CLIENT_SESSION_DEAD){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}
	// AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK

	return session->recv_ring_buf_used;
}

bool ptp_is_dead(void *ptp_handle){
	if (ptp_handle == NULL){
		return true;
	}

	struct ptp_session *session = (struct ptp_session *)ptp_handle;
	if (session->dead || session->abort){
		return true;
	}

	if (hung_up_wrapped(session->sock, session->enet_handle)){
		LOG("%s: the other side closed the listen socket\n", __func__);
		session->dead = true;
		close_wrapped(session->sock, session->enet_handle);
		return true;
	}

	return false;
}

int ptp_send_buf_not_full(void *ptp_handle){
	if (ptp_is_dead(ptp_handle)){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	struct ptp_session *session = ptp_handle;

	return send_buf_not_full_wrapped(session->sock, session->enet_handle);
}

bool ptp_listen_is_dead(void *ptp_listen_handle){
	if (ptp_listen_handle == NULL){
		return true;
	}

	struct ptp_listen_session *session = (struct ptp_listen_session *)ptp_listen_handle;
	if (session->dead){
		return true;
	}

	if (hung_up_wrapped(session->sock, session->enet_handle)){
		LOG("%s: the other side closed the listen socket\n", __func__);
		session->dead = true;
		close_wrapped(session->sock, session->enet_handle);
		return true;
	}

	return false;
}

int ptp_listen_has_request(void *ptp_listen_handle){
	if (ptp_listen_handle == NULL){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (ptp_listen_is_dead(ptp_listen_handle)){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	struct ptp_listen_session *session = (struct ptp_listen_session *)ptp_listen_handle;

	struct aemu_postoffice_ptp_connect connect_packet;
	int peek_result = peek_wrapped(session->sock, session->enet_handle, (char *)&connect_packet, sizeof(connect_packet));
	if (peek_result == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
		return 0;
	}
	if (peek_result == 0){
		LOG("%s: the other side closed the listen socket\n", __func__);
		session->dead = true;
		close_wrapped(session->sock, session->enet_handle);
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}
	if (peek_result <= 0){
		LOG("%s: socket error\n", __func__);
		session->dead = true;
		close_wrapped(session->sock, session->enet_handle);
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}
	if (peek_result != sizeof(connect_packet)){
		return 0;
	}
	return 1;
}
