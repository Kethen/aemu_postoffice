#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "postoffice_client.h"

#include "../aemu_postoffice_packets.h"

#define LOG(...){ \
	fprintf(stderr, __VA_ARGS__); \
}

struct pdp_session{
	char *pdp_mac[6];
	int16_t pdp_port;
	int sock;
	bool dead;
};

struct ptp_listen_session{
	char *ptp_mac[6];
	int16_t ptp_port;
	int sock;
	bool dead;
	int domain;
	struct sockaddr_in6 addr;
	int addrlen;
};

struct ptp_session{
	int sock;
	bool dead;
	char outstanding_data[2048];
	int outstanding_data_size;
	int outstanding_data_offset;
};

static int send_till_done(int fd, const char *buf, int len, bool non_block){
	int write_offset = 0;
	while(write_offset != len){
		int write_status = send(fd, &buf[write_offset], len - write_offset, MSG_DONTWAIT);
		if (write_status == -1){
			int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK){
				if (non_block && write_offset == 0){
					return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
				}
				// Continue block sending, either in block mode or we already received part of the message
				continue;
			}
			// Other errors
			return write_status;
		}
		write_offset += write_status;
	}
	return write_offset;
}

static int recv_till_done(int fd, char *buf, int len, bool non_block){
	int read_offset = 0;
	while(read_offset != len){
		int recv_status = recv(fd, &buf[read_offset], len - read_offset, MSG_DONTWAIT);
		if (recv_status <= 0){
			int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK){
				if (non_block && read_offset == 0){
					return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
				}
				// Continue block receving, either in block mode or we already sent part of the message
				continue;
			}
			// Other errors
			return recv_status;
		}
		read_offset += recv_status;
	}
	return read_offset;
}

static int create_and_init_socket(int domain, struct sockaddr *addr, int addrlen, const char *init_packet, int init_packet_len, const char *caller_name){
	int sock = socket(domain, SOCK_STREAM, 0);
	if (sock == -1){
		LOG("%s: failed creating socket, %s\n", caller_name, strerror(errno));
		return AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
	}

	// Set socket options
	int sockopt = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt));

	// Connect
	int connect_status = connect(sock, addr, addrlen);
	if (connect_status == -1){
		LOG("%s: failed connecting, %s\n", caller_name, strerror(errno));
		close(sock);
		return AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
	}

	int write_status = send_till_done(sock, (char *)init_packet, init_packet_len, false);
	if (write_status == -1){
		LOG("%s: failed sending init packet, %s\n", caller_name, strerror(errno));
		close(sock);
		return AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
	}

	return sock;
}

static void *pdp_create(int domain, struct sockaddr *addr, socklen_t addrlen, const char *pdp_mac, int pdp_port, int *state){
	struct pdp_session* session = (struct pdp_session*)malloc(sizeof(struct pdp_session));
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

	int sock = create_and_init_socket(domain, addr, addrlen, (char *)&init_packet, sizeof(init_packet), __func__);

	if (sock < 0){
		*state = sock;
		free(session);
		return NULL;
	}

	memcpy(session->pdp_mac, pdp_mac, 6);
	session->pdp_port = pdp_port;
	session->sock = sock;
	session->dead = false;

	*state = AEMU_POSTOFFICE_CLIENT_OK;
	return session;
}

void *pdp_create_v6(struct in6_addr addr, int port, const char *pdp_mac, int pdp_port, int *state){
	struct sockaddr_in6 addrv6 = {0};
	addrv6.sin6_family = AF_INET6;
	addrv6.sin6_port = htons(port);
	addrv6.sin6_addr = addr;

	return pdp_create(AF_INET6, (struct sockaddr *)&addrv6, sizeof(addrv6), pdp_mac, pdp_port, state);
}
void *pdp_create_v4(struct in_addr addr, int port, const char *pdp_mac, int pdp_port, int *state){
	struct sockaddr_in addrv4 = {0};
	addrv4.sin_family = AF_INET;
	addrv4.sin_port = htons(port);
	addrv4.sin_addr = addr;

	return pdp_create(AF_INET, (struct sockaddr *)&addrv4, sizeof(addrv4), pdp_mac, pdp_port, state);
}

int pdp_send(void *pdp_handle, const char *pdp_mac, int pdp_port, const char *buf, int len, bool non_block){
	if (pdp_handle == NULL){
		return -1;
	}
	struct pdp_session *session = (struct pdp_session *)pdp_handle;
	if (session->dead){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (len > 2048){
		LOG("%s: failed sending data, data too big, %d\n", __func__, len);
		return AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY;
	}

	char send_buf[2048 + sizeof(struct aemu_postoffice_pdp)];

	// Write header
	struct aemu_postoffice_pdp *pdp_header = (struct aemu_postoffice_pdp *)send_buf;
	memcpy(pdp_header->addr, pdp_mac, 6);
	pdp_header->port = pdp_port;
	pdp_header->size = len;

	// Copy data into send buffer
	memcpy(&send_buf[sizeof(struct aemu_postoffice_pdp)], buf, len);

	int send_status = send_till_done(session->sock, send_buf, sizeof(struct aemu_postoffice_pdp) + len, non_block);
	if (send_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	if (send_status < 0){
		// Error
		LOG("%s: failed sending data, %s\n", __func__, strerror(errno));
		session->dead = true;
		close(session->sock);
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}
	return AEMU_POSTOFFICE_CLIENT_OK;
}

int pdp_recv(void *pdp_handle, char *pdp_mac, int *pdp_port, char *buf, int *len, bool non_block){
	if (pdp_handle == NULL){
		return -1;
	}
	struct pdp_session *session = (struct pdp_session *)pdp_handle;
	if (session->dead){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}	

	if (*len > 2048){
		return AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY;
	}

	struct aemu_postoffice_pdp pdp_header;
	int recv_status = recv_till_done(session->sock, (char *)&pdp_header, sizeof(pdp_header), non_block);
	if (recv_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	if (recv_status == 0){
		LOG("%s: remote closed the socket\n", __func__);
		close(session->sock);
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (recv_status == -1){
		LOG("%s: failed receiving data, %s\n", __func__, strerror(errno));
		close(session->sock);
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	// We have a header
	if (pdp_header.size > 2048){
		// The other side is sending packets that are too big
		LOG("%s: failed receiving data, data too big %d\n", __func__, pdp_header.size);
		close(session->sock);
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (pdp_mac != NULL)
		memcpy(pdp_mac, pdp_header.addr, 6);
	if (pdp_port != NULL)
		*pdp_port = pdp_header.port;

	char recv_buf[2048];
	recv_status = recv_till_done(session->sock, recv_buf, pdp_header.size, false);

	if (recv_status == 0){
		LOG("%s: remote closed the socket\n", __func__);
		close(session->sock);
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (recv_status == -1){
		LOG("%s: failed receiving data, %s\n", __func__, strerror(errno));
		close(session->sock);
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	// We have data
	memcpy(buf, recv_buf, *len);
	if (pdp_header.size > *len){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DATA_TRUNC;
	}
	*len = pdp_header.size;
	return AEMU_POSTOFFICE_CLIENT_OK;
}

void pdp_delete(void *pdp_handle){
	if (pdp_handle == NULL){
		return;
	}
	struct pdp_session *session = (struct pdp_session *)pdp_handle;
	if (!session->dead)
		close(session->sock);
	free(session);
}


static void *ptp_listen(int domain, struct sockaddr *addr, socklen_t addrlen, const char *ptp_mac, int ptp_port, int *state){
	struct ptp_listen_session* session = (struct ptp_listen_session*)malloc(sizeof(struct ptp_listen_session));
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

	int sock = create_and_init_socket(domain, addr, addrlen, (char *)&init_packet, sizeof(init_packet), __func__);

	if (sock < 0){
		*state = sock;
		free(session);
		return NULL;
	}

	memcpy(session->ptp_mac, ptp_mac, 6);
	session->ptp_port = ptp_port;
	session->sock = sock;
	session->domain = domain;
	memcpy(&session->addr, addr, addrlen);
	session->addrlen = addrlen;
	session->dead = false;

	*state = AEMU_POSTOFFICE_CLIENT_OK;
	return session;
}

void *ptp_listen_v6(struct in6_addr addr, int port, const char *ptp_mac, int ptp_port, int *state){
	struct sockaddr_in6 addrv6 = {0};
	addrv6.sin6_family = AF_INET6;
	addrv6.sin6_port = htons(port);
	addrv6.sin6_addr = addr;

	return ptp_listen(AF_INET6, (struct sockaddr *)&addrv6, sizeof(addrv6), ptp_mac, ptp_port, state);
}

void *ptp_listen_v4(struct in_addr addr, int port, const char *ptp_mac, int ptp_port, int *state){
	struct sockaddr_in addrv4 = {0};
	addrv4.sin_family = AF_INET;
	addrv4.sin_port = htons(port);
	addrv4.sin_addr = addr;

	return ptp_listen(AF_INET, (struct sockaddr *)&addrv4, sizeof(addrv4), ptp_mac, ptp_port, state);
}

void *ptp_accept(void *ptp_listen_handle, bool nonblock, int *state){
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
	int recv_status = recv_till_done(session->sock, (char *)&connect_packet, sizeof(connect_packet), nonblock);
	if (recv_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
		return NULL;
	}
	if (recv_status == 0){
		LOG("%s: the other side closed the listen socket\n", __func__);
		session->dead = true;
		close(session->sock);
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		return NULL;
	}
	if (recv_status <= 0){
		LOG("%s: socket error, %d %s\n", __func__, recv_status, strerror(errno));
		session->dead = true;
		close(session->sock);
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
		return NULL;
	}

	// Allocate memory
	struct ptp_session *new_session = (struct ptp_session *)malloc(sizeof(struct ptp_session));
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

	int sock = create_and_init_socket(session->domain, (struct sockaddr *)&session->addr, session->addrlen, (char *)&init_packet, sizeof(init_packet), __func__);

	if (sock < 0){
		*state = sock;
		free(new_session);
		return NULL;
	}

	// Consume the ack packet
	int read_status = recv_till_done(sock, (char *)&connect_packet, sizeof(connect_packet), false);
	if (read_status == 0){
		LOG("%s: remove closed the socket during initial recv\n", __func__);
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		close(sock);
		free(new_session);
		return NULL;
	}
	if (read_status == -1){
		LOG("%s: socket error receiving initial packet, %s\n", __func__, strerror(errno));
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		close(sock);
		free(new_session);
		return NULL;
	}

	// Now the session is ready
	new_session->sock = sock;
	new_session->dead = false;
	new_session->outstanding_data_size = 0;
	*state = AEMU_POSTOFFICE_CLIENT_OK;
	return new_session;
}

static void *ptp_connect(int domain, struct sockaddr *addr, int addrlen, const char *src_ptp_mac, int ptp_sport, const char *dst_ptp_mac, int ptp_dport, int *state){
	// Allocate memory
	struct ptp_session *new_session = (struct ptp_session *)malloc(sizeof(struct ptp_session));
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

	int sock = create_and_init_socket(domain, addr, addrlen, (char *)&init_packet, sizeof(init_packet), __func__);

	if (sock < 0){
		*state = sock;
		free(new_session);
		return NULL;
	}

	// Consume the ack packet
	struct aemu_postoffice_ptp_connect connect_packet;
	int read_status = recv_till_done(sock, (char *)&connect_packet, sizeof(connect_packet), false);
	if (read_status == 0){
		LOG("%s: remove closed the socket during initial recv\n", __func__);
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		close(sock);
		free(new_session);
		return NULL;
	}
	if (read_status == -1){
		LOG("%s: socket error receiving initial packet, %s\n", __func__, strerror(errno));
		*state = AEMU_POSTOFFICE_CLIENT_SESSION_NETWORK;
		close(sock);
		free(new_session);
		return NULL;
	}

	// Now the session is ready
	new_session->sock = sock;
	new_session->dead = false;
	new_session->outstanding_data_size = 0;
	*state = AEMU_POSTOFFICE_CLIENT_OK;
	return new_session;
}

void *ptp_connect_v6(struct in6_addr addr, int port, const char *src_ptp_mac, int ptp_sport, const char *dst_ptp_mac, int ptp_dport, int *state){
	struct sockaddr_in6 addrv6 = {0};
	addrv6.sin6_family = AF_INET6;
	addrv6.sin6_port = htons(port);
	addrv6.sin6_addr = addr;

	return ptp_connect(AF_INET6, (struct sockaddr *)&addrv6, sizeof(addrv6), src_ptp_mac, ptp_sport, dst_ptp_mac, ptp_dport, state);
}

void *ptp_connect_v4(struct in_addr addr, int port, const char *src_ptp_mac, int ptp_sport, const char *dst_ptp_mac, int ptp_dport, int *state){
	struct sockaddr_in addrv4 = {0};
	addrv4.sin_family = AF_INET;
	addrv4.sin_port = htons(port);
	addrv4.sin_addr = addr;

	return ptp_connect(AF_INET, (struct sockaddr *)&addrv4, sizeof(addrv4), src_ptp_mac, ptp_sport, dst_ptp_mac, ptp_dport, state);
}

int ptp_send(void *ptp_handle, const char *buf, int len, bool non_block){
	if (ptp_handle == NULL){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	struct ptp_session *session = (struct ptp_session *)ptp_handle;
	if (session->dead){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (len > 2048){
		LOG("%s: failed sending data, data too big, %d\n", __func__, len);
		return AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY;
	}

	struct aemu_postoffice_ptp_data header = {
		.size = len
	};

	int send_status = send_till_done(session->sock, (char *)&header, sizeof(header), non_block);
	if (send_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	if (send_status < 0){
		LOG("%s: failed sending header, %s\n", __func__, strerror(errno));
		close(session->sock);
		session->dead = true;
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	send_status = send_till_done(session->sock, buf, len, false);
	if (send_status < 0){
		LOG("%s: failed sending data, %s\n", __func__, strerror(errno));
		close(session->sock);
		session->dead = true;
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	return AEMU_POSTOFFICE_CLIENT_OK;
}

int ptp_recv(void *ptp_handle, char *buf, int *len, bool non_block){
	if (ptp_handle == NULL){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	struct ptp_session *session = (struct ptp_session *)ptp_handle;
	if (session->dead){
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (*len > 2048){
		LOG("%s: failed receiving data, data too big, %d\n", __func__, len);
		return AEMU_POSTOFFICE_CLIENT_OUT_OF_MEMORY;
	}

	// check if we have outstanding transfer
	if (session->outstanding_data_size != 0){
		memcpy(buf, &session->outstanding_data[session->outstanding_data_offset], *len);
		if (session->outstanding_data_size > *len){
			session->outstanding_data_size -= *len;
			session->outstanding_data_offset += *len;
			return AEMU_POSTOFFICE_CLIENT_SESSION_DATA_TRUNC;
		}

		*len = session->outstanding_data_size;
		session->outstanding_data_size = 0;
		return AEMU_POSTOFFICE_CLIENT_OK;
	}

	struct aemu_postoffice_ptp_data header = {0};
	

	int recv_status = recv_till_done(session->sock, (char *)&header, sizeof(header), non_block);
	if (recv_status == AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
		return AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK;
	}

	if (recv_status == 0){
		LOG("%s: remote closed the socket\n", __func__);
		close(session->sock);
		session->dead = true;
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (recv_status < 0){
		LOG("%s: failed receiving header, %s\n", __func__, strerror(errno));
		close(session->sock);
		session->dead = true;
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (header.size > 2048){
		LOG("%s: incoming data too big\n", __func__);
		close(session->sock);
		session->dead = true;
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	char recv_buf[2048];
	recv_status = recv_till_done(session->sock, recv_buf, header.size, false);

	if (recv_status == 0){
		LOG("%s: remote closed the socket\n", __func__);
		close(session->sock);
		session->dead = true;
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	if (recv_status < 0){
		LOG("%s: failed receiving data, %s\n", __func__, strerror(errno));
		close(session->sock);
		session->dead = true;
		return AEMU_POSTOFFICE_CLIENT_SESSION_DEAD;
	}

	memcpy(buf, recv_buf, *len);
	if (*len < header.size){
		session->outstanding_data_offset = 0;
		session->outstanding_data_size = header.size - *len;
		memcpy(session->outstanding_data, &recv_buf[*len], session->outstanding_data_size);
		return AEMU_POSTOFFICE_CLIENT_SESSION_DATA_TRUNC;
	}
	*len = header.size;
	return AEMU_POSTOFFICE_CLIENT_OK;
}

void ptp_close(void *ptp_handle){
	if (ptp_handle == NULL){
		return;
	}

	struct ptp_session *session = (struct ptp_session *)ptp_handle;
	if (!session->dead)
		close(session->sock);
	free(session);
}

void ptp_listen_close(void *ptp_listen_handle){
	if (ptp_listen_handle == NULL){
		return;
	}

	struct ptp_listen_session *session = (struct ptp_listen_session *)ptp_listen_handle;
	if (!session->dead)
		close(session->sock);
	free(session);
}
