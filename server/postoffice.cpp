#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>

#include <string.h>

#include <map>
#include <vector>
#include <string>
#include <functional>

#include "log.h"
#include "../aemu_postoffice_packets.h"

struct pending_session{
	int sock;
	timespec timestamp;
	in6_addr addr;
	int port;
	int recv_offset;
	char recv_buffer[sizeof(aemu_postoffice_init)];
};

struct post_office_session;
struct post_office_context{
	pthread_mutex_t pending_sessions_mutex;
	std::vector<pending_session> pending_sessions;

	pthread_mutex_t active_sessions_mutex;
	std::map<std::string, post_office_session> active_sessions;
	int max_threads;

	bool pending_session_worker_stop;
};

typedef enum{
	SESSION_PDP,
	SESSION_PTP_LISTEN,
	SESSION_PTP_CONNECT,
	SESSION_PTP_ACCEPT
} session_type;

typedef enum{
	SESSION_THREAD_RUNNING,
	SESSION_THREAD_STOPPING,
	SESSION_THREAD_STOPPED
} session_thread_state;

typedef enum{
	SESSION_RECV_HEADER = 0,
	SESSION_RECV_DATA,
} session_recv_state;

struct post_office_session{
	session_type type;
	int sock;
	int pipe[2];
	pthread_mutex_t pipe_in_mutex;
	char src[6];
	int sport;
	char dst[6];
	int dport;
	pthread_t thread;
	bool should_stop;
	session_thread_state thread_state;
	post_office_context *context;
	std::string session_name;
	std::string bond_session_name_listen;
	std::string bond_session_name_connect;
	std::string bond_session_name_accept;
};

struct post_office_pipe_packet{
	uint32_t size;
};

static const char* get_socket_error(){
	// WINDOWS TODO
	return strerror(errno);
}

static int get_socket_error_num(){
	// WINDOWS_TODO
	return errno;
}

static int sprintv6(char *buf, const in6_addr &addr){
	int offset = 0;
	for(int i = 0;i < 16;i++){
		offset += sprintf(&buf[offset], "%02x", addr.s6_addr[i]);
		if (i % 2 != 0 && i != 15)
			offset += sprintf(&buf[offset], ":");
	}
	return offset;
}

static int read_till_done(int fd, char *buf, uint32_t size, std::function<bool()> should_stop){
	int read_offset = 0;
	while(read_offset != size && !should_stop()){
		int read_status = read(fd, &buf[read_offset], size - read_offset);
		int err = 0;
		if (read_status == -1){
			err = get_socket_error_num();
		}
		if (read_status == -1 && (err == EAGAIN || err == EWOULDBLOCK)){
			continue;
		}
		if (read_status <= 0){
			return read_status;
		}
		read_offset += read_status;
	}
	if(should_stop()){
		return -1;
	}
	return read_offset;
}

static int write_till_done(int fd, const char *buf, uint32_t size, std::function<bool()> should_stop){
	int write_offset = 0;
	while(write_offset != size && !should_stop()){
		int write_status = write(fd, &buf[write_offset], size - write_offset);
		int err = 0;
		if (write_status == -1){
			err = get_socket_error_num();
		}
		if (write_status == -1 && (err == EAGAIN || err == EWOULDBLOCK)){
			continue;
		}
		if (write_status <= 0){
			return write_status;
		}
		write_offset += write_status;
	}
	if(should_stop()){
		return -1;
	}
	return write_offset;
}

static void session_worker_pdp(post_office_session &session){
	auto should_stop = [session] () {
		return session.should_stop;
	};

	auto should_not_stop = [] () {return false;};

	while(!session.should_stop){
		pollfd fds[2] = {0};
		fds[0].fd = session.pipe[0];
		fds[0].events = POLLIN;
		fds[1].fd = session.sock;
		fds[1].events = POLLIN;

		int poll_status = poll(fds, 2, 100);
		if (poll_status == EINTR){
			continue;
		}
		if (poll_status == -1){
			// Dead poll, critical
			LOG("%s: Cannot poll, %s\n", __func__, get_socket_error());
			break;
		}

		if (fds[0].revents & POLLERR){
			LOG("%s: poll error on pipe, terminating\n", __func__);
			break;
		}

		if (fds[1].revents & POLLERR){
			LOG("%s: poll error on tcp socket, terminating\n", __func__);
			break;
		}

		if (fds[0].revents & POLLIN){
			char pipe_data_buffer[4096 + sizeof(aemu_postoffice_pdp)];
			aemu_postoffice_pdp &pipe_packet_header = *(aemu_postoffice_pdp *)pipe_data_buffer;

			int read_status = read_till_done(session.pipe[0], pipe_data_buffer, sizeof(pipe_packet_header), should_stop);
			if (read_status <= 0){
				// The other side closed it prematurely, critical
				LOG("%s: pipe read closed prematurely, %s\n", __func__, get_socket_error());
				break;
			}

			if (pipe_packet_header.size > 4096){
				// Critical error for this thread
				LOG("%s: incoming pipe data too big\n", __func__);
				break;
			}

			read_status = read_till_done(session.pipe[0], &pipe_data_buffer[sizeof(pipe_packet_header)], pipe_packet_header.size, should_stop);
			if (read_status <= 0){
				// The other side closed it prematurely, critical
				LOG("%s: pipe read closed prematurely, %d, %s\n", __func__, read_status, get_socket_error());
				break;
			}

			// Source address should be filled in the header already by the other side of the pipe
			int write_status = write_till_done(session.sock, pipe_data_buffer, sizeof(pipe_packet_header) + pipe_packet_header.size, should_stop);
			if (write_status <= 0){
				// The other side closed it, critical
				LOG("%s: tcp write closed prematurely, %s\n", __func__, get_socket_error());
				break;
			}
		}

		if (fds[1].revents & POLLIN){
			char tcp_data_buffer[4096 + sizeof(aemu_postoffice_pdp)];
			aemu_postoffice_pdp &tcp_packet_header = *(aemu_postoffice_pdp *)tcp_data_buffer;

			int read_status = read_till_done(session.sock, tcp_data_buffer, sizeof(tcp_packet_header), should_stop);
			if (read_status <= 0){
				// The other side closed it, critical
				LOG("%s: tcp read closed prematurely during header fetch, %d %s\n", __func__, read_status, get_socket_error());
				break;
			}

			if (tcp_packet_header.size > 4096){
				// Critical error for this thread
				LOG("%s: incoming tcp data too big\n", __func__);
				break;
			}

			read_status = read_till_done(session.sock, &tcp_data_buffer[sizeof(tcp_packet_header)], tcp_packet_header.size, should_stop);
			if (read_status <= 0){
				// The other side closed it, critical
				LOG("%s: tcp read closed prematurely during data fetch, %s\n", __func__, get_socket_error());
				break;
			}

			// Derive traget session name
			char target_session_name[256] = {0};
			sprintf(target_session_name, "PDP %x:%x:%x:%x:%x:%x %d", (uint8_t)tcp_packet_header.addr[0], (uint8_t)tcp_packet_header.addr[1], (uint8_t)tcp_packet_header.addr[2], (uint8_t)tcp_packet_header.addr[3], (uint8_t)tcp_packet_header.addr[4], (uint8_t)tcp_packet_header.addr[5], tcp_packet_header.port);
			std::string target_session_name_str = std::string(target_session_name);

			// Fill in our own data
			memcpy(tcp_packet_header.addr, session.src, 6);
			tcp_packet_header.port = session.sport;

			// Now to find the other side
			int session_list_lock_status = -1;
			while(!session.should_stop){
				session_list_lock_status = pthread_mutex_trylock(&session.context->active_sessions_mutex);
				if (session_list_lock_status == EBUSY){
					continue;
				}
				break;
			}
			if (session_list_lock_status != 0){
				// If the global active session lock is dead, it is critical
				LOG("%s: active session lock locking error, 0x%x\n", __func__, session_list_lock_status);
				break;
			}

			auto send_to_session = session.context->active_sessions.find(target_session_name_str);
			if (send_to_session == session.context->active_sessions.end()){
				// We don't have to send it if it doesn't exist
				pthread_mutex_unlock(&session.context->active_sessions_mutex);
				continue;
			}

			int pipe_lock_status = pthread_mutex_lock(&send_to_session->second.pipe_in_mutex);
			if (pipe_lock_status != 0){
				// The lock is destroyed, target session is taking itself down
				pthread_mutex_unlock(&session.context->active_sessions_mutex);
				continue;
			}

			pthread_mutex_unlock(&session.context->active_sessions_mutex);

			// Now we send, the send status doesn't really matter right now because if it fails, it doesn't concern us here, the other side is cleaning up
			// Always send the full packet, even if we were asked to stop, only stop if the other side closes the pipe
			int send_status = write_till_done(send_to_session->second.pipe[1], tcp_data_buffer, sizeof(tcp_packet_header) + tcp_packet_header.size, should_not_stop);
			pthread_mutex_unlock(&send_to_session->second.pipe_in_mutex);
		}
	}
}

static void session_worker_ptp_listen(post_office_session &session){
	auto should_stop = [session] () {
		return session.should_stop;
	};

	auto should_not_stop = [] {return false;};

	while(!session.should_stop){
		pollfd pfd = {0};
		pfd.fd = session.pipe[0];
		pfd.events = POLLIN;

		int poll_status = poll(&pfd, 1, 100);
		if (poll_status == EINTR){
			continue;
		}
		if (poll_status == -1){
			// Dead poll, critical
			LOG("%s: Cannot poll, %s\n", __func__, get_socket_error());
			break;
		}

		if (pfd.revents & POLLERR){
			LOG("%s: poll error on pipe, terminating\n", __func__);
			break;
		}

		// Test if the other side have closed the socket
		char recv_test_buf[4];
		int recv_status = recv(session.sock, &recv_test_buf, sizeof(recv_test_buf), MSG_DONTWAIT);
		if (recv_status == -1){
			int err = errno;
			if (err != EAGAIN && err != EWOULDBLOCK){
				// The socket died
				LOG("%s: tcp socket died, terminating\n", __func__);
				break;
			}
		}
		if (recv_status == 0){
			// The other side closed the socket
			LOG("%s: client closed the socket, terminating\n", __func__);
			break;
		}

		if (pfd.revents & POLLIN){
			// Connect side has found the listen side, and have already prepared this packet
			aemu_postoffice_ptp_connect connect_packet;
			int read_status = read_till_done(session.pipe[0], (char *)&connect_packet, sizeof(connect_packet), should_not_stop);
			// The other side has to send the packet in full
			if (read_status <= 0){
				// Ignore it
				LOG("%s: bad incoming connect request on pipe, please debug this\n", __func__);
				continue;
			}

			int write_status = write_till_done(session.sock, (char *)&connect_packet, sizeof(connect_packet), should_stop);
			if (write_status == -1){
				// This is critical to this thread
				LOG("%s: failed writing connect request, %d %s\n", __func__, write_status, get_socket_error());
				break;
			}
		}
	}
}

static void session_worker_ptp(post_office_session &session){
	bool notified = session.type == SESSION_PTP_CONNECT ? false : true;
	bool connected = false;
	bool device_notified = false;
	timespec begin;
	clock_gettime(CLOCK_BOOTTIME, &begin);

	auto should_stop = [session] () {
		return session.should_stop;
	};

	auto should_not_stop = [] {return false;};

	std::string target_session_name_str = session.type == SESSION_PTP_CONNECT ? session.bond_session_name_accept : session.bond_session_name_connect;

	while(!session.should_stop){
		pollfd fds[2] = {0};
		fds[0].fd = session.pipe[0];
		fds[0].events = POLLIN;
		fds[1].fd = session.sock;
		fds[1].events = POLLIN;

		int poll_status = poll(fds, 2, 100);
		if (poll_status == EINTR){
			continue;
		}
		if (poll_status == -1){
			// Dead poll, critical
			LOG("%s: Cannot poll, %s\n", __func__, get_socket_error());
			break;
		}

		if (fds[0].revents & POLLERR){
			LOG("%s: poll error on pipe, terminating\n", __func__);
			break;
		}

		if (fds[1].revents & POLLERR){
			LOG("%s: poll error on tcp socket, terminating\n", __func__);
			break;
		}

		if (!connected || !notified){
			timespec now;
			clock_gettime(CLOCK_BOOTTIME, &now);
			if (now.tv_sec - begin.tv_sec > 20){
				LOG("%s: the other side was not found in 20 seconds, disconnecting, notified %d connected %d\n", __func__, notified, connected);
				break;
			}

			if (!notified){
				int session_list_lock_status = -1;
				while(!session.should_stop){
					session_list_lock_status = pthread_mutex_trylock(&session.context->active_sessions_mutex);
					if (session_list_lock_status == EBUSY){
						continue;
					}
					break;
				}
				if (session_list_lock_status != 0){
					// This is critical
					LOG("%s: active session lock locking error, 0x%x\n", __func__, session_list_lock_status);
					break;
				}

				auto notify_session = session.context->active_sessions.find(session.bond_session_name_listen);
				if (notify_session == session.context->active_sessions.end()){
					// Target not found, try again later
					pthread_mutex_unlock(&session.context->active_sessions_mutex);
					continue;
				}
				// Target found
				int lock_status = pthread_mutex_lock(&notify_session->second.pipe_in_mutex);
				pthread_mutex_unlock(&session.context->active_sessions_mutex);

				if (lock_status != 0){
					// The other side is spinning down
					LOG("%s: listen session is spinning down while trying to notify\n", __func__);
					break;
				}

				aemu_postoffice_ptp_connect connect_packet;
				memcpy(connect_packet.addr, session.src, 6);
				connect_packet.port = session.sport;

				int write_status = write_till_done(notify_session->second.pipe[1], (char *)&connect_packet, sizeof(connect_packet), should_not_stop);
				if (write_status == -1){
					LOG("%s: failed writing to listen session, %d %s\n", write_status, strerror(errno));
					pthread_mutex_unlock(&notify_session->second.pipe_in_mutex);
					break;
				}

				pthread_mutex_unlock(&notify_session->second.pipe_in_mutex);
				notified = true;
			}

			if (!connected){
				// Block progress utill the other side is found
				int session_list_lock_status = -1;
				while(!session.should_stop){
					session_list_lock_status = pthread_mutex_trylock(&session.context->active_sessions_mutex);
					if (session_list_lock_status == EBUSY){
						continue;
					}
					break;
				}
				if (session_list_lock_status != 0){
					// This is critical
					LOG("%s: active session lock locking error, 0x%x\n", __func__, session_list_lock_status);
					break;
				}

				auto target_session = session.context->active_sessions.find(target_session_name_str);
				if (target_session == session.context->active_sessions.end()){
					// Target not found
					pthread_mutex_unlock(&session.context->active_sessions_mutex);
					continue;
				}
				pthread_mutex_unlock(&session.context->active_sessions_mutex);

				// Target was found
				connected = true;
			}
		}

		if (!device_notified){
			// Notify the device that after this read, it will be data
			aemu_postoffice_ptp_connect connect_packet;
			memcpy(connect_packet.addr, session.dst, 6);
			connect_packet.port = session.dport;

			int write_status = write_till_done(session.sock, (char *)&connect_packet, sizeof(connect_packet), should_stop);
			if (write_status == -1){
				// Failed writing notifiy packet to device, this is fatal
				break;
			}

			device_notified = true;
		}

		if (fds[0].revents & POLLIN){
			char pipe_in_buffer[4096 + sizeof(aemu_postoffice_ptp_data)];
			aemu_postoffice_ptp_data *data_packet = (aemu_postoffice_ptp_data *)pipe_in_buffer;

			int read_status = read_till_done(session.pipe[0], pipe_in_buffer, sizeof(aemu_postoffice_ptp_data), should_not_stop);
			if (read_status <= 0){
				// This is critical for this thread
				LOG("%s: failed reading from pipe during header read\n", __func__);
				break;
			}

			if (data_packet->size > 4096){
				// This is an assertion
				LOG("%s: data too big, please debug this\n", __func__);
				break;
			}

			read_status = read_till_done(session.pipe[0], &pipe_in_buffer[sizeof(aemu_postoffice_ptp_data)], data_packet->size, should_not_stop);
			if (read_status <= 0){
				// This is critical for this thread
				LOG("%s: failed reading from pipe during data read\n", __func__);
				break;
			}

			// Now send to our socket
			int write_status = write_till_done(session.sock, pipe_in_buffer, data_packet->size + sizeof(aemu_postoffice_ptp_data), should_stop);
			if (write_status == -1){
				// This is critical for this thread
				LOG("%s: failed forwarding pipe data to tcp socket\n", __func__);
				break;
			}
		}

		if (fds[1].revents & POLLIN){
			char tcp_data_buffer[sizeof(aemu_postoffice_ptp_data) + 4096];
			aemu_postoffice_ptp_data *tcp_packet_header = (aemu_postoffice_ptp_data *)tcp_data_buffer;
			int read_status = read_till_done(session.sock, tcp_data_buffer, sizeof(aemu_postoffice_ptp_data), should_stop);
			if (read_status == 0){
				LOG("%s: remote closed the connection during header read\n", __func__);
				break;
			}
			if (read_status < 0){
				LOG("%s: socket error during header read, %d %s\n", __func__, strerror(errno));
				break;
			}

			if (tcp_packet_header->size > 4096){
				// This is critical for this thread
				LOG("%s: incoming data from tcp is too big\n", __func__);
				break;
			}

			read_status = read_till_done(session.sock, &tcp_data_buffer[sizeof(aemu_postoffice_ptp_data)], tcp_packet_header->size, should_stop);
			if (read_status == 0){
				LOG("%s: remote closed the connection during header read\n", __func__);
				break;
			}
			if (read_status < 0){
				LOG("%s: socket error during header read, %d %s\n", __func__, strerror(errno));
				break;
			}

			// Now to find the other side
			int session_list_lock_status = -1;
			while(!session.should_stop){
				session_list_lock_status = pthread_mutex_trylock(&session.context->active_sessions_mutex);
				if (session_list_lock_status == EBUSY){
					continue;
				}
				break;
			}
			if (session_list_lock_status != 0){
				// If the global active session lock is dead, it is critical
				LOG("%s: active session lock locking error, 0x%x\n", __func__, session_list_lock_status);
				break;
			}

			auto send_to_session = session.context->active_sessions.find(target_session_name_str);
			if (send_to_session == session.context->active_sessions.end()){
				// The other side went away
				LOG("%s: bond connection was spun down\n", __func__);
				pthread_mutex_unlock(&session.context->active_sessions_mutex);
				break;
			}

			int pipe_lock_status = pthread_mutex_lock(&send_to_session->second.pipe_in_mutex);
			pthread_mutex_unlock(&session.context->active_sessions_mutex);

			if (pipe_lock_status != 0){
				// The lock is destroyed, target session is taking itself down
				LOG("%s: bond connection is spinning down\n", __func__);
				break;
			}

			// Now we send, the send status doesn't really matter right now because if it fails, it doesn't concern us here, the other side is cleaning up
			// Always send the full packet, even if we were asked to stop, only stop if the other side closes the pipe
			int send_status = write_till_done(send_to_session->second.pipe[1], tcp_data_buffer, sizeof(aemu_postoffice_ptp_data) + tcp_packet_header->size, should_not_stop);
			pthread_mutex_unlock(&send_to_session->second.pipe_in_mutex);
		}
	}

	// Try to bring down the other side as well
	do{
		int session_list_lock_status = pthread_mutex_lock(&session.context->active_sessions_mutex);
		if (session_list_lock_status != 0){
			// If the global active session lock is dead, it is critical
			LOG("%s: active session lock locking error during termination, 0x%x\n", __func__, session_list_lock_status);
			break;
		}

		auto terminate_session = session.context->active_sessions.find(target_session_name_str);
		if (terminate_session != session.context->active_sessions.end()){
			terminate_session->second.should_stop = true;
		}

		pthread_mutex_unlock(&session.context->active_sessions_mutex);
	}while(false);
}

static void *session_worker(void *arg){
	post_office_session &session = *(post_office_session *)arg;
	switch(session.type){
		case SESSION_PDP:{
			session_worker_pdp(session);
			break;
		}
		case SESSION_PTP_LISTEN:{
			session_worker_ptp_listen(session);
			break;
		}
		case SESSION_PTP_ACCEPT:
		case SESSION_PTP_CONNECT:{
			session_worker_ptp(session);
			break;
		}
	}

	session.thread_state = SESSION_THREAD_STOPPING;

	// Common cleanup
	close(session.pipe[0]);
	close(session.pipe[1]);
	close(session.sock);
	while(pthread_mutex_destroy(&session.pipe_in_mutex) != 0);

	session.thread_state = SESSION_THREAD_STOPPED;
	return NULL;
}

static void *pending_session_worker(void *arg){
	post_office_context &context = *(post_office_context*)arg;
	while(!context.pending_session_worker_stop){
		// Reap finished sessions
		pthread_mutex_lock(&context.active_sessions_mutex);
		for(auto session = context.active_sessions.begin();session != context.active_sessions.end();){
			if(session->second.thread_state == SESSION_THREAD_STOPPED){
				LOG("%s: %s has finished\n", __func__, session->first.c_str());
				pthread_join(session->second.thread, NULL);
				context.active_sessions.erase(session);
				session = context.active_sessions.begin();
				continue;
			}
			session++;
		}
		pthread_mutex_unlock(&context.active_sessions_mutex);

		static const timespec thread_delay = {
			.tv_sec = 0,
			.tv_nsec = 1000000000 / 4
		};

		int try_lock_status = pthread_mutex_trylock(&context.pending_sessions_mutex);
		if (try_lock_status != 0){
			nanosleep(&thread_delay, NULL);			
			continue;
		}

		#define UNLOCK_CONTINUE() { \
			pthread_mutex_unlock(&context.pending_sessions_mutex); \
			nanosleep(&thread_delay, NULL); \
			continue; \
		}

		static const int pending_session_timeout_sec = 5;

		timespec now;
		clock_gettime(CLOCK_BOOTTIME, &now);

		// Promote pending sessions to real sessions
		for(int i = 0;i < context.pending_sessions.size();i++){
			auto &session = context.pending_sessions[i];
			char v6_str[256] = {0};
			sprintv6(v6_str, session.addr);

			if (now.tv_sec - session.timestamp.tv_sec > pending_session_timeout_sec){
				LOG("%s: remote %s timed out before an init packet is received\n", __func__, v6_str);
				close(session.sock);
				context.pending_sessions.erase(context.pending_sessions.begin() + i);
				i--;
				continue;
			}

			bool try_again_later = false;
			int err = 0;
			bool terminated = false;
			while(session.recv_offset < sizeof(aemu_postoffice_init)){
				int recv_status = recv(session.sock, &session.recv_buffer[session.recv_offset], sizeof(aemu_postoffice_init) - session.recv_offset, MSG_DONTWAIT);
				if (recv_status == -1){
					err = get_socket_error_num();
					if (err == EAGAIN || err == EWOULDBLOCK){
						try_again_later = true;
					}
					break;
				}
				if (recv_status == 0){
					terminated = true;
					break;
				}
				session.recv_offset += recv_status;
			}

			if (try_again_later){
				continue;
			}

			if (terminated || err){
				if (terminated){
					LOG("%s: remote %s terminated before an init packet is received\n", __func__, v6_str);
				}else{
					LOG("%s: remote %s errored before an init packet is received, %s\n", __func__, v6_str, get_socket_error());
				}
				close(session.sock);
				context.pending_sessions.erase(context.pending_sessions.begin() + i);
				i--;
				continue;
			}

			if (session.recv_offset != sizeof(aemu_postoffice_init)){
				// more to receive
				continue;
			}

			aemu_postoffice_init *init_packet = (aemu_postoffice_init *)session.recv_buffer;
			pthread_mutex_lock(&context.active_sessions_mutex);
			if (context.active_sessions.size() == context.max_threads){
				LOG("%s: remote %s sent init packet, but we are at thread limit\n", __func__, v6_str);
				close(session.sock);
				context.pending_sessions.erase(context.pending_sessions.begin() + i);
				i--;
				pthread_mutex_unlock(&context.active_sessions_mutex);
				continue;
			}

			post_office_session new_session;
			pipe(new_session.pipe);
			fcntl(new_session.pipe[0], F_SETFL, fcntl(new_session.pipe[0], F_GETFL, 0) | O_NONBLOCK);
			fcntl(new_session.pipe[1], F_SETFL, fcntl(new_session.pipe[1], F_GETFL, 0) | O_NONBLOCK);
			fcntl(new_session.sock, F_SETFL, fcntl(new_session.sock, F_GETFL, 0) | O_NONBLOCK);
			new_session.thread_state = SESSION_THREAD_RUNNING;
			new_session.context = &context;
			new_session.sock = session.sock;
			new_session.sport = init_packet->sport;
			memcpy(new_session.src, init_packet->src_addr, 6);
			new_session.dport = init_packet->dport;
			memcpy(new_session.dst, init_packet->dst_addr, 6);

			char session_name[256] = {0};

			switch(init_packet->init_type){
				case AEMU_POSTOFFICE_INIT_PDP:{
					new_session.type = SESSION_PDP;
					sprintf(session_name, "PDP %x:%x:%x:%x:%x:%x %d", (uint8_t)new_session.src[0], (uint8_t)new_session.src[1], (uint8_t)new_session.src[2], (uint8_t)new_session.src[3], (uint8_t)new_session.src[4], (uint8_t)new_session.src[5], new_session.sport);
					break;
				}
				case AEMU_POSTOFFICE_INIT_PTP_LISTEN:{
					new_session.type = SESSION_PTP_LISTEN;
					sprintf(session_name, "PTP LISTEN %x:%x:%x:%x:%x:%x %d", (uint8_t)new_session.src[0], (uint8_t)new_session.src[1], (uint8_t)new_session.src[2], (uint8_t)new_session.src[3], (uint8_t)new_session.src[4], (uint8_t)new_session.src[5], new_session.sport);
					break;
				}
				case AEMU_POSTOFFICE_INIT_PTP_CONNECT:{
					new_session.type = SESSION_PTP_CONNECT;
					sprintf(session_name, "PTP CONNECT %x:%x:%x:%x:%x:%x %d %x:%x:%x:%x:%x:%x %d", (uint8_t)new_session.src[0], (uint8_t)new_session.src[1], (uint8_t)new_session.src[2], (uint8_t)new_session.src[3], (uint8_t)new_session.src[4], (uint8_t)new_session.src[5], new_session.sport, (uint8_t)new_session.dst[0], (uint8_t)new_session.dst[1], (uint8_t)new_session.dst[2], (uint8_t)new_session.dst[3], (uint8_t)new_session.dst[4], (uint8_t)new_session.dst[5], new_session.dport);

					// Search for the other side
					char target_session_name[256];
					sprintf(target_session_name, "PTP LISTEN %x:%x:%x:%x:%x:%x %d", (uint8_t)new_session.dst[0], (uint8_t)new_session.dst[1], (uint8_t)new_session.dst[2], (uint8_t)new_session.dst[3], (uint8_t)new_session.dst[4], (uint8_t)new_session.dst[5], new_session.dport);
					std::string target_session_name_str = std::string(target_session_name);
					if (context.active_sessions.find(target_session_name) == context.active_sessions.end()){
						// Target not found, close the connection
						LOG("%s: %s wants to connect to %s, but it was not found\n", __func__, session_name, target_session_name);
						close(session.sock);
						context.pending_sessions.erase(context.pending_sessions.begin() + i);
						i--;
						pthread_mutex_unlock(&context.active_sessions_mutex);
						continue;
					}
					new_session.bond_session_name_listen = target_session_name_str;
					sprintf(target_session_name, "PTP ACCEPT %x:%x:%x:%x:%x:%x %d %x:%x:%x:%x:%x:%x %d", (uint8_t)new_session.dst[0], (uint8_t)new_session.dst[1], (uint8_t)new_session.dst[2], (uint8_t)new_session.dst[3], (uint8_t)new_session.dst[4], (uint8_t)new_session.dst[5], new_session.dport, (uint8_t)new_session.src[0], (uint8_t)new_session.src[1], (uint8_t)new_session.src[2], (uint8_t)new_session.src[3], (uint8_t)new_session.src[4], (uint8_t)new_session.src[5], new_session.sport);

					new_session.bond_session_name_accept = std::string(target_session_name);
					break;
				}
				case AEMU_POSTOFFICE_INIT_PTP_ACCEPT:{
					new_session.type = SESSION_PTP_ACCEPT;
					sprintf(session_name, "PTP ACCEPT %x:%x:%x:%x:%x:%x %d %x:%x:%x:%x:%x:%x %d", (uint8_t)new_session.src[0], (uint8_t)new_session.src[1], (uint8_t)new_session.src[2], (uint8_t)new_session.src[3], (uint8_t)new_session.src[4], (uint8_t)new_session.src[5], new_session.sport, (uint8_t)new_session.dst[0], (uint8_t)new_session.dst[1], (uint8_t)new_session.dst[2], (uint8_t)new_session.dst[3], (uint8_t)new_session.dst[4], (uint8_t)new_session.dst[5], new_session.dport);

					// Search for the other side
					char target_session_name[256];
					sprintf(target_session_name, "PTP CONNECT %x:%x:%x:%x:%x:%x %d %x:%x:%x:%x:%x:%x %d", (uint8_t)new_session.dst[0], (uint8_t)new_session.dst[1], (uint8_t)new_session.dst[2], (uint8_t)new_session.dst[3], (uint8_t)new_session.dst[4], (uint8_t)new_session.dst[5], new_session.dport, (uint8_t)new_session.src[0], (uint8_t)new_session.src[1], (uint8_t)new_session.src[2], (uint8_t)new_session.src[3], (uint8_t)new_session.src[4], (uint8_t)new_session.src[5], new_session.sport);
					std::string target_session_name_str = std::string(target_session_name);
					if (context.active_sessions.find(target_session_name) == context.active_sessions.end()){
						// Target not found, close the connection
						LOG("%s: %s wants to connect to %s, but it was not found\n", __func__, session_name, target_session_name);
						close(session.sock);
						context.pending_sessions.erase(context.pending_sessions.begin() + i);
						i--;
						pthread_mutex_unlock(&context.active_sessions_mutex);
						continue;
					}
					new_session.bond_session_name_connect = target_session_name_str;
					break;
				}
				default:{
					LOG("%s: %d is not yet implemented\n", __func__, init_packet->init_type);
					close(session.sock);
					context.pending_sessions.erase(context.pending_sessions.begin() + i);
					i--;
					pthread_mutex_unlock(&context.active_sessions_mutex);
					continue;
				}
			}

			std::string session_name_str = std::string(session_name);
			new_session.session_name = session_name_str;

			auto existing_session = context.active_sessions.find(session_name_str);
			if (existing_session != context.active_sessions.end()){
				// kick the previous mapping?
				LOG("%s: kicking existing mapping with the same session name %s\n", __func__, session_name);
				existing_session->second.should_stop = true;
				pthread_join(existing_session->second.thread, NULL);
				context.active_sessions.erase(existing_session);
			}

			context.active_sessions[session_name_str] = new_session;

			auto &new_session_ref = context.active_sessions[session_name_str];
			pthread_mutex_init(&new_session_ref.pipe_in_mutex, NULL);

			new_session_ref.should_stop = false;
			int thread_create_status = pthread_create(&new_session_ref.thread, NULL, session_worker, &new_session_ref);
			if (thread_create_status != 0){
				LOG("%s: failed creating thread for %s\n", __func__, v6_str);
				pthread_mutex_destroy(&new_session_ref.pipe_in_mutex);
				close(new_session_ref.pipe[0]);
				close(new_session_ref.pipe[1]);
				close(session.sock);
				context.active_sessions.erase(session_name_str);
				context.pending_sessions.erase(context.pending_sessions.begin() + i);
				i--;
				pthread_mutex_unlock(&context.active_sessions_mutex);
				continue;
			}
			pthread_setname_np(new_session_ref.thread, "session worker");


			// New session thread created at this point
			pthread_mutex_unlock(&context.active_sessions_mutex);
			context.pending_sessions.erase(context.pending_sessions.begin() + i);
			i--;
			LOG("%s: session for %s created, %s\n", __func__, v6_str, session_name);
		}

		UNLOCK_CONTINUE();
	}
	return NULL;
}

extern "C" {
int start_postoffice(int port, int max_threads, int max_pending_sessions, bool *stop_thread){
	init_logging();
	LOG("%s: Starting aemu postoffice on port %d, with %d max threads, %d max pending sessions\n", __func__, port, max_threads, max_pending_sessions);

	// WINDOWS TODO remember to start WS2 before using WS2

	post_office_context context;

	pthread_mutex_init(&context.pending_sessions_mutex, NULL);
	pthread_mutex_init(&context.active_sessions_mutex, NULL);
	context.max_threads = max_threads;

	context.pending_session_worker_stop = false;

	int main_socket = socket(AF_INET6, SOCK_STREAM, 0);
	if (main_socket == -1){
		LOG("%s: failed creating ipv6 socket, %s, terminating\n", __func__, get_socket_error());
		return -1;
	}

	int sockopt = 1;
	setsockopt(main_socket, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt));
	// 2 seconds, if you don't ack in 2 seconds you get dropped
	sockopt = 2000;
	setsockopt(main_socket, IPPROTO_TCP, TCP_USER_TIMEOUT, &sockopt, sizeof(sockopt));
	// We initiate keep alive for the client to keep client load low
	sockopt = 1;
	setsockopt(main_socket, SOL_SOCKET, SO_KEEPALIVE, &sockopt, sizeof(sockopt));

	// emulators can use v6
	sockaddr_in6 addr6 = {0};
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = IN6ADDR_ANY_INIT;
	addr6.sin6_port = htons(port);

	int bind_status = bind(main_socket, (sockaddr *)&addr6, sizeof(addr6));
	if (bind_status == -1){
		LOG("%s: failed binding ipv6 socket, %s, terminating\n", __func__, get_socket_error());
		close(main_socket);
		return -1;
	}

	int listen_status = listen(main_socket, 100);
	if (listen_status == -1){
		LOG("%s: failed setting up socket for listening, %s, terminating\n", __func__, get_socket_error());
		close(main_socket);
		return -1;
	}

	int exit_status = 0;

	pthread_t pending_session_thread;
	int thread_create_status = pthread_create(&pending_session_thread, NULL, pending_session_worker, &context);
	if (thread_create_status != 0){
		LOG("%s: failed starting pending session work thread, 0x%x, terminating\n", __func__, thread_create_status);
		close(main_socket);
		return -1;
	}
	pthread_setname_np(pending_session_thread, "pending session worker");

	LOG("%s: accepting connections\n", __func__);
	while(!*stop_thread){
		pollfd p = {0};
		p.fd = main_socket;
		p.events = POLLIN;

		int poll_status = poll(&p, 1, 1000);
		if (poll_status == -1){
			// WINDOWS TODO
			if (errno == EINTR){
				continue;
			}
			const char *err = get_socket_error();
			LOG("%s: failed polling, %s, terminating\n", __func__, get_socket_error());
			break;
		}

		// We have an incoming connection
		sockaddr_in6 incoming_addr = {0};
		socklen_t addr_size = sizeof(incoming_addr);

		int accept_status = accept(main_socket, (sockaddr *)&incoming_addr, &addr_size);
		if (accept_status == -1){
			LOG("%s: accept failed, %s\n", __func__, get_socket_error());
			continue;
		}

		pending_session new_session = {
			.sock = accept_status,
			.addr = incoming_addr.sin6_addr,
			.port = ntohs(incoming_addr.sin6_port),
		};
		clock_gettime(CLOCK_BOOTTIME, &new_session.timestamp);

		pending_session popped = {0};

		pthread_mutex_lock(&context.pending_sessions_mutex);
		context.pending_sessions.insert(context.pending_sessions.begin(), new_session);
		if (context.pending_sessions.size() > max_pending_sessions){
			popped = context.pending_sessions[context.pending_sessions.size() - 1];
			context.pending_sessions.pop_back();
		}
		pthread_mutex_unlock(&context.pending_sessions_mutex);

		if (popped.port != 0){
			close(popped.sock);
			char v6_str[256];
			sprintv6(v6_str, popped.addr);
			LOG("%s: removed pending session %s %d since we have %d pending sessions\n", __func__, v6_str, popped.port, context.pending_sessions.size());
		}

		char v6_str[256];
		sprintv6(v6_str, incoming_addr.sin6_addr);

		LOG("%s: added %s %d to pending sessions\n", __func__, v6_str, new_session.port);
	}

	context.pending_session_worker_stop = true;
	pthread_join(pending_session_thread, NULL);
	// Stop all pending sessions
	for(int i = 0;i < context.pending_sessions.size();i++){
		close(context.pending_sessions[i].sock);
	}
	// Stop all active sessions
	for(auto session = context.active_sessions.begin();session != context.active_sessions.end();session++){
		session->second.thread_state = SESSION_THREAD_STOPPING;
		pthread_join(session->second.thread, NULL);
	}
	close(main_socket);
	int mutex_delete_status = pthread_mutex_destroy(&context.active_sessions_mutex);
	if (mutex_delete_status != 0){
		LOG("%s: failed removing active sessions mutex, 0x%x\n", __func__, mutex_delete_status);
	}
	mutex_delete_status = pthread_mutex_destroy(&context.pending_sessions_mutex);
	if (mutex_delete_status != 0){
		LOG("%s: failed removing pending sessions mutex, 0x%x\n", __func__, mutex_delete_status);
	}
	
	return exit_status;
}
}

