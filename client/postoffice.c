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

static int write_till_done(int fd, const char *buf, int len){
	int write_offset = 0;
	while(write_offset != len){
		int write_status = write(fd, &buf[write_offset], len - write_offset);
		if (write_status == -1){
			return write_status;
		}
		write_offset += write_status;
	}
	return write_offset;
}

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

static void *pdp_create(int domain, struct sockaddr *addr, socklen_t addrlen, const char *pdp_mac, int pdp_port){
	int sock = socket(domain, SOCK_STREAM, 0);
	if (sock == -1){
		LOG("%s: failed creating socket, %s\n", __func__, strerror(errno));
		return NULL;
	}

	// Set socket options
	int sockopt = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt));

	// Prepare init packet
	struct aemu_postoffice_init init_packet = {0};
	init_packet.init_type = AEMU_POSTOFFICE_INIT_PDP;
	memcpy(init_packet.src_addr, pdp_mac, 6);
	init_packet.sport = pdp_port;

	// Connect
	int connect_status = connect(sock, addr, addrlen);
	if (connect_status == -1){
		LOG("%s: failed connecting, %s\n", __func__, strerror(errno));
		close(sock);
		return NULL;
	}

	// Send init packet
	int write_status = write_till_done(sock, (char *)&init_packet, sizeof(init_packet));
	if (write_status != sizeof(init_packet)){
		LOG("%s: failed sending init packet, %s\n", __func__, strerror(errno));
		close(sock);
		return NULL;
	}

	// Socket ready
	struct pdp_session* session = (struct pdp_session*)malloc(sizeof(struct pdp_session));
	if (session == NULL){
		LOG("%s: failed allocating memory for pdp session\n", __func__);
		close(sock);
		return NULL;
	}

	// Memory allocated
	memcpy(session->pdp_mac, pdp_mac, 6);
	session->pdp_port = pdp_port;
	session->sock = sock;

	return (void *)session;
}

void *pdp_create_v6(struct in6_addr addr, int port, const char *pdp_mac, int pdp_port){
	struct sockaddr_in6 addrv6 = {0};
	addrv6.sin6_family = AF_INET6;
	addrv6.sin6_port = htons(port);
	addrv6.sin6_addr = addr;

	return pdp_create(AF_INET6, (struct sockaddr *)&addrv6, sizeof(addrv6), pdp_mac, pdp_port);
}
void *pdp_create_v4(struct in_addr addr, int port, const char *pdp_mac, int pdp_port){
	struct sockaddr_in addrv4 = {0};
	addrv4.sin_family = AF_INET;
	addrv4.sin_port = htons(port);
	addrv4.sin_addr = addr;

	return pdp_create(AF_INET, (struct sockaddr *)&addrv4, sizeof(addrv4), pdp_mac, pdp_port);
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
	close(session->sock);
	free(session);
}
