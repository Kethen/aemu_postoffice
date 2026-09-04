#include <stdlib.h>
#include <string.h>

#include "session.h"
#include "native_socket.h"
#include "log.h"

#include "../aemu_postoffice_packets.h"

namespace aemu_postoffice_server {

PendingSession::PendingSession(int sock_fd, std::string client_addr, int client_port, struct config *config){
	this->sock_fd = sock_fd;
	this->client_addr = client_addr;
	this->client_port = client_port;
	this->create_time = std::chrono::high_resolution_clock::now();
	this->config = config;
	LOG("%s: %s connecting\n", __func__, client_addr.c_str());
}

static std::string get_listen_session_name(const char *mac, uint16_t port){
	char buf[128] = {0};
	snprintf(buf, sizeof(buf), "PTP_LISTEN %02x:%02x:%02x:%02x:%02x:%02x %u", (uint8_t)mac[0], (uint8_t)mac[1], (uint8_t)mac[2], (uint8_t)mac[3], (uint8_t)mac[4], (uint8_t)mac[5], port);
	return std::string(buf);
}

static std::string get_connect_session_name(const char *src_addr, uint16_t sport, const char *dst_addr, uint16_t dport){
	char buf[128] = {0};
	snprintf(buf, sizeof(buf), "PTP_CONNECT %02x:%02x:%02x:%02x:%02x:%02x %u %02x:%02x:%02x:%02x:%02x:%02x %u",
			(uint8_t)src_addr[0], (uint8_t)src_addr[1], (uint8_t)src_addr[2], (uint8_t)src_addr[3], (uint8_t)src_addr[4], (uint8_t)src_addr[5], sport,
			(uint8_t)dst_addr[0], (uint8_t)dst_addr[1], (uint8_t)dst_addr[2], (uint8_t)dst_addr[3], (uint8_t)dst_addr[4], (uint8_t)dst_addr[5], dport);
	return std::string(buf);
}

static std::string get_accept_session_name(const char *src_addr, uint16_t sport, const char *dst_addr, uint16_t dport){
	char buf[128] = {0};
	snprintf(buf, sizeof(buf), "PTP_ACCEPT %02x:%02x:%02x:%02x:%02x:%02x %u %02x:%02x:%02x:%02x:%02x:%02x %u",
			(uint8_t)src_addr[0], (uint8_t)src_addr[1], (uint8_t)src_addr[2], (uint8_t)src_addr[3], (uint8_t)src_addr[4], (uint8_t)src_addr[5], sport,
			(uint8_t)dst_addr[0], (uint8_t)dst_addr[1], (uint8_t)dst_addr[2], (uint8_t)dst_addr[3], (uint8_t)dst_addr[4], (uint8_t)dst_addr[5], dport);
	return std::string(buf);
}

static std::string get_pdp_session_name(const char *mac, uint16_t port){
	char buf[128] = {0};
	snprintf(buf, sizeof(buf), "PDP %02x:%02x:%02x:%02x:%02x:%02x %u", (uint8_t)mac[0], (uint8_t)mac[1], (uint8_t)mac[2], (uint8_t)mac[3], (uint8_t)mac[4], (uint8_t)mac[5], port);
	return std::string(buf);
}

PendingSessionPumpStatus PendingSession::pump(std::unordered_map<std::string, Session> &global_sessions, const aemu_postoffice_adhocctl_server::snapshot &adhocctl_snapshot){
	char buf[sizeof(aemu_postoffice_init)];

	if ((std::chrono::high_resolution_clock::now() - this->create_time) / std::chrono::milliseconds(1) > this->config->session_init_time_limit_ms){
		LOG("%s: session creation for %s timed out\n", __func__, this->client_addr.c_str());
		native_close(this->sock_fd);
		return PendingSessionPumpStatus::TIMEOUT;
	}

	int recv_status = native_recv(this->sock_fd, buf, sizeof(buf));
	if (recv_status == 0){
		LOG("%s: client %s closed socket during init\n", __func__, this->client_addr.c_str());
		native_close(this->sock_fd);
		return PendingSessionPumpStatus::SOCKET_CLOSED;
	}
	if (recv_status < 0){
		int error = native_get_last_socket_error();
		if (!native_error_is_would_block(error)){
			LOG("%s: client %s has socket error 0x%x during init\n", __func__, this->client_addr.c_str(), error);
			native_close(this->sock_fd);
			return PendingSessionPumpStatus::SOCKET_CLOSED;
		}
	}
	if (recv_status > 0){
		// can be <0 if we got a would block, which happens during connect wait
		init_data_buffer.append(buf, recv_status);
	}

	if (init_data_buffer.length() >= sizeof(aemu_postoffice_init)){
		const aemu_postoffice_init *init = (const aemu_postoffice_init *)init_data_buffer.data();
		auto strict_mode_check = [this, init, &adhocctl_snapshot] () -> bool{
			if (!this->config->strict_mode){
				return true;
			}

			std::string src_mac(init->src_addr, 6);
			auto src_client = adhocctl_snapshot.clients.find(src_mac);
			if (src_client == adhocctl_snapshot.clients.end()){
				// src client not found (yet)
				return false;
			}

			if (client_addr != src_client->second.ip){
				// ip does not match (yet)
				return false;
			}

			auto game = adhocctl_snapshot.games.find(src_client->second.game_code);
			auto group = game->second.groups.find(src_client->second.group_key);
			if (group->second.channel < 0){
				// client has not joined a group (yet)
				return false;
			}

			if (init->init_type == AEMU_POSTOFFICE_INIT_PTP_ACCEPT || init->init_type == AEMU_POSTOFFICE_INIT_PTP_CONNECT){
				// in the case of ptp accept and connect, make sure both are in the same group
				std::string dst_mac(init->dst_addr, 6);

				bool dst_found_in_group = false;
				for (auto &member_mac : group->second.members){
					if (member_mac == dst_mac){
						dst_found_in_group = true;
						break;
					}
				}
				if (!dst_found_in_group){
					// dst is not in the same group (yet)
					return false;
				}
			}
			return true;
		};
		switch(init->init_type){
			case AEMU_POSTOFFICE_INIT_PTP_LISTEN:
			case AEMU_POSTOFFICE_INIT_PDP:{
				return strict_mode_check() ? PendingSessionPumpStatus::SESSION_READY : PendingSessionPumpStatus::SUCCESS;
			}
			case AEMU_POSTOFFICE_INIT_PTP_CONNECT:{
				std::string listen_session_name = get_listen_session_name(init->dst_addr, init->dport);
				if (global_sessions.find(listen_session_name) == global_sessions.end()){
					// allow connect to slightly wait for listen to come into existence
					return PendingSessionPumpStatus::SUCCESS;
				}else{
					// one must call create_session before changes happen to the global session map
					return strict_mode_check() ? PendingSessionPumpStatus::SESSION_READY : PendingSessionPumpStatus::SUCCESS;
				}
			}
			case AEMU_POSTOFFICE_INIT_PTP_ACCEPT:{
				std::string connect_session_name = get_connect_session_name(init->dst_addr, init->dport, init->src_addr, init->sport);
				auto connect_session = global_sessions.find(connect_session_name);
				if (connect_session == global_sessions.end() || connect_session->second.get_session_phase() != SessionPhase::PTP_CONNECTING){
					LOG("%s: peer session %s not found, not creating ptp accept session for %s\n", __func__, connect_session_name.c_str(), this->client_addr.c_str());
					native_close(this->sock_fd);
					return PendingSessionPumpStatus::SOCKET_CLOSED;
				}else{
					// one must call create_session before changes happen to the global session map
					return strict_mode_check() ? PendingSessionPumpStatus::SESSION_READY : PendingSessionPumpStatus::SUCCESS;
				}
			}
			default:{
				LOG("%s: unknown init type %d, not creating session for %s\n", __func__, init->init_type, this->client_addr.c_str());
				native_close(this->sock_fd);
				return PendingSessionPumpStatus::BAD_INIT;
			}
		}
	}
	return PendingSessionPumpStatus::SUCCESS;
}

Session PendingSession::create_session(std::unordered_map<std::string, Session> &global_sessions){
	aemu_postoffice_init init;
	memcpy(&init, this->init_data_buffer.data(), sizeof(init));
	this->init_data_buffer.erase(0, sizeof(init));
	switch(init.init_type){
		case AEMU_POSTOFFICE_INIT_PDP:{
			return Session(SessionMode::PDP, init.src_addr, init.sport, NULL, 0, this->init_data_buffer, this->sock_fd, NULL, this->client_addr, this->client_port, this->config);
		}
		case AEMU_POSTOFFICE_INIT_PTP_LISTEN:{
			this->init_data_buffer = std::string("");
			return Session(SessionMode::PTP_LISTEN, init.src_addr, init.sport, NULL, 0, this->init_data_buffer, this->sock_fd, NULL, this->client_addr, this->client_port, this->config);
		}
		case AEMU_POSTOFFICE_INIT_PTP_CONNECT:{
			std::string listen_session_name = get_listen_session_name(init.dst_addr, init.dport);
			auto listen_session = global_sessions.find(listen_session_name);
			if (listen_session == global_sessions.end()){
				LOG("%s: critical, ptp listen session removed during ptp connect session creation, fix this\n", __func__);
				exit(1);
			}
			return Session(SessionMode::PTP_CONNECT, init.src_addr, init.sport, init.dst_addr, init.dport, this->init_data_buffer, this->sock_fd, &listen_session->second, this->client_addr, this->client_port, this->config);
		}
		case AEMU_POSTOFFICE_INIT_PTP_ACCEPT:{
			std::string connect_session_name = get_connect_session_name(init.dst_addr, init.dport, init.src_addr, init.sport);
			auto connect_session = global_sessions.find(connect_session_name);
			if (connect_session == global_sessions.end()){
				LOG("%s: critical, ptp connect session removed during accept session creation, fix this\n", __func__);
				exit(1);
			}
			return Session(SessionMode::PTP_ACCEPT, init.src_addr, init.sport, init.dst_addr, init.dport, this->init_data_buffer, this->sock_fd, &connect_session->second, this->client_addr, this->client_port, this->config);
		}
		default:{
			LOG("%s: critical, unknown init type %d during session creation, fix this\n", __func__, init.init_type);
			exit(1);
			return Session(SessionMode::PDP, NULL, 0, NULL, 0, std::string(""), 0, NULL, std::string(""), 0, NULL);
		}
	}
}

void PendingSession::close_socket(){
	if (this->sock_fd != -1){
		native_close(this->sock_fd);
		this->sock_fd = -1;
	}
}

Session::Session(SessionMode mode, char *from_mac, uint16_t from_port, char *to_mac, uint16_t to_port, std::string initial_data_buffer, int sock_fd, Session *peer_session, std::string client_addr, int client_port, struct config *config){
	this->mode = mode;
	this->config = config;

	this->from_mac = std::string(from_mac, 6);
	this->from_port = from_port;
	if (to_mac != NULL){
		this->to_mac = std::string(to_mac, 6);
	}
	this->to_port = to_port;
	this->sock_fd = sock_fd;
	this->create_time = std::chrono::high_resolution_clock::now();
	this->client_addr = client_addr;
	this->client_port = client_port;
	this->phase = SessionPhase::HEADER;
	if (mode != SessionMode::PTP_LISTEN){
		this->from_client_data_buffer = initial_data_buffer;
	}
	if (mode == SessionMode::PTP_CONNECT){
		// queue listen session notification
		aemu_postoffice_ptp_connect to_listen_session = {0};
		memcpy(to_listen_session.addr, this->from_mac.data(), 6);
		to_listen_session.port = this->from_port;
		SendListItem send_req = {
			peer_session->get_identifier(),
			this->from_mac,
			std::string((char *)&to_listen_session, sizeof(to_listen_session)),
		};
		this->send_list.push_back(send_req);

		this->phase = SessionPhase::PTP_CONNECTING;
	}
	if (mode == SessionMode::PTP_ACCEPT){
		aemu_postoffice_ptp_connect packet = {0};

		// queue data mode activation
		memcpy(packet.addr, this->from_mac.data(), 6);
		packet.port = this->from_port;
		SendListItem send_req = {
			peer_session->get_identifier(),
			this->from_mac,
			std::string((char *)&packet, sizeof(packet)),
		};
		this->send_list.push_back(send_req);

		memcpy(packet.addr, peer_session->from_mac.data(), 6);
		packet.port = peer_session->from_port;
		send_req.session_name = this->get_identifier();
		send_req.from_mac = peer_session->get_from_mac();
		send_req.data = std::string((char *)&packet, sizeof(packet));
		peer_session->send_list.push_back(send_req);

		this->phase = SessionPhase::HEADER;
		peer_session->phase = SessionPhase::HEADER;

		LOG("%s: bonding %s with %s\n", __func__, peer_session->get_identifier().c_str(), this->get_identifier().c_str());
	}

	LOG("%s: created session %s for %s\n", __func__, this->get_identifier().c_str(), this->client_addr.c_str());
}

Session::~Session(){
}

SessionPumpStatus Session::pump_connect(){
	if (this->mode != SessionMode::PTP_CONNECT){
		return SessionPumpStatus::SUCCESS;
	}
	if (this->phase != SessionPhase::PTP_CONNECTING){
		return SessionPumpStatus::CONNECTED;
	}
	if ((std::chrono::high_resolution_clock::now() - this->create_time) / std::chrono::milliseconds(1) > this->config->connect_time_limit_ms){
		return SessionPumpStatus::TIMEOUT;
	}
	return SessionPumpStatus::SUCCESS;
}

SessionPumpStatus Session::pump_from_client(){
	SessionPumpStatus ret = SessionPumpStatus::SUCCESS;

	while(true){
		char buf[1024];
		int recv_status = native_recv(this->sock_fd, buf, sizeof(buf));
		if (recv_status == 0){
			LOG("%s: client %s of session %s has closed the socket\n", __func__, this->client_addr.c_str(), this->get_identifier().c_str());
			ret = SessionPumpStatus::SOCKET_CLOSED;
			break;
		}
		if (recv_status < 0){
			int error = native_get_last_socket_error();
			if (native_error_is_would_block(error)){
				ret = SessionPumpStatus::SUCCESS;
				break;
			}
			LOG("%s: socket error 0x%x on session %s with client %s\n", __func__, error, this->get_identifier().c_str(), this->client_addr.c_str());
			ret = SessionPumpStatus::SOCKET_CLOSED;
			break;
		}

		if (this->mode == SessionMode::PTP_LISTEN){
			// we don't handle data from user listen session
			continue;
		}

		this->from_client_data_buffer.append(buf, recv_status);
	}

	while(this->mode != SessionMode::PTP_LISTEN && this->phase != SessionPhase::PTP_CONNECTING){
		if (this->phase == SessionPhase::HEADER){
			if (this->mode == SessionMode::PDP){
				if (this->from_client_data_buffer.length() >= sizeof(aemu_postoffice_pdp)){
					aemu_postoffice_pdp *header = (aemu_postoffice_pdp *)this->from_client_data_buffer.data();
					this->pdp_data_target = get_pdp_session_name(header->addr, header->port);
					this->data_size = header->size;
					if (this->data_size > AEMU_POSTOFFICE_PDP_BLOCK_MAX * 2){
						return SessionPumpStatus::BAD_DATA_SIZE;
					}
					this->from_client_data_buffer.erase(0, sizeof(aemu_postoffice_pdp));
					this->phase = SessionPhase::DATA;
					continue;
				}
			}else{
				if (this->from_client_data_buffer.length() >= sizeof(aemu_postoffice_ptp_data)){
					aemu_postoffice_ptp_data *header = (aemu_postoffice_ptp_data *)this->from_client_data_buffer.data();
					this->data_size = header->size;
					if (this->data_size > AEMU_POSTOFFICE_PTP_BLOCK_MAX * 2){
						return SessionPumpStatus::BAD_DATA_SIZE;
					}
					this->from_client_data_buffer.erase(0, sizeof(aemu_postoffice_ptp_data));
					this->phase = SessionPhase::DATA;
					continue;
				}
			}
		}else{
			if (this->mode == SessionMode::PDP){
				if (this->from_client_data_buffer.length() >= this->data_size){
					char *buf = (char *)calloc(1, sizeof(aemu_postoffice_pdp) + this->data_size);
					if (buf == NULL){
						LOG("%s: out of memory!", __func__);
						exit(1);
					}
					memcpy(&buf[sizeof(aemu_postoffice_pdp)], this->from_client_data_buffer.data(), this->data_size);
					this->from_client_data_buffer.erase(0, this->data_size);

					aemu_postoffice_pdp *header = (aemu_postoffice_pdp *)buf;
					memcpy(header->addr, this->from_mac.data(), 6);
					header->port = this->from_port;
					header->size = this->data_size;
					SendListItem send_req = {
						this->pdp_data_target,
						this->from_mac,
						std::string(buf, sizeof(aemu_postoffice_pdp) + this->data_size),
					};
					free(buf);
					this->send_list.push_back(send_req);
					this->phase = SessionPhase::HEADER;
					continue;
				}
			}else{
				if (this->from_client_data_buffer.length() >= this->data_size){
					char *buf = (char *)calloc(1, sizeof(aemu_postoffice_ptp_data) + this->data_size);
					if (buf == NULL){
						LOG("%s: out of memory!", __func__);
						exit(1);
					}
					memcpy(&buf[sizeof(aemu_postoffice_ptp_data)], this->from_client_data_buffer.data(), this->data_size);
					this->from_client_data_buffer.erase(0, this->data_size);

					aemu_postoffice_ptp_data *header = (aemu_postoffice_ptp_data *)buf;
					header->size = this->data_size;
					SendListItem send_req = {
						this->get_peer_identifier(),
						this->from_mac,
						std::string(buf, sizeof(aemu_postoffice_ptp_data) + this->data_size),
					};
					free(buf);
					this->send_list.push_back(send_req);
					this->phase = SessionPhase::HEADER;
					continue;
				}
			}
		}

		break;
	}

	return ret;
}

void Session::get_send_list(std::vector<SendListItem> &container){
	std::swap(container, this->send_list);
	this->send_list.clear();
}

DataQueueStatus Session::queue_send(const std::string &data){
	to_client_data_buffer.append(data.data(), data.length());
	if (to_client_data_buffer.length() >= this->config->data_queue_size_limit_byte){
		LOG("%s: session %s from %s has reached receive data buffer limit %ub\n", __func__, this->get_identifier().c_str(), this->get_client_addr().c_str(), this->config->data_queue_size_limit_byte);
		return DataQueueStatus::MAX_DATA_REACHED;
	}
	return DataQueueStatus::SUCCESS;
}

SessionPumpStatus Session::pump_to_client(){
	while(true){
		if (to_client_data_buffer.length() == 0){
			return SessionPumpStatus::SUCCESS;
		}

		int send_status = native_send(this->sock_fd, to_client_data_buffer.data(), to_client_data_buffer.length());
		if (send_status < 0){
			int error = native_get_last_socket_error();
			if (native_error_is_would_block(error)){
				 return SessionPumpStatus::SUCCESS;
			}
			LOG("%s: sock error 0x%x on session %s with client %s\n", __func__, error, this->get_identifier().c_str(), this->client_addr.c_str());
			return SessionPumpStatus::SOCKET_CLOSED;
		}
		to_client_data_buffer.erase(0, send_status);
	}
}

std::string Session::get_identifier(){
	switch(this->mode){
		case SessionMode::PDP:{
			return get_pdp_session_name(this->from_mac.data(), this->from_port);
		}
		case SessionMode::PTP_LISTEN:{
			return get_listen_session_name(this->from_mac.data(), this->from_port);
		}
		case SessionMode::PTP_CONNECT:{
			return get_connect_session_name(this->from_mac.data(), this->from_port, this->to_mac.data(), this->to_port);
		}
		case SessionMode::PTP_ACCEPT:{
			return get_accept_session_name(this->from_mac.data(), this->from_port, this->to_mac.data(), this->to_port);
		}
	}
	LOG("%s: bad session mode 0x%x, debug this\n", __func__, this->mode);
	return std::string("");
}

std::string Session::get_peer_identifier(){
	switch(this->mode){
		case SessionMode::PDP:
		case SessionMode::PTP_LISTEN:{
			return std::string("");
		}
		case SessionMode::PTP_CONNECT:{
			return get_accept_session_name(this->to_mac.data(), this->to_port, this->from_mac.data(), this->from_port);
		}
		case SessionMode::PTP_ACCEPT:{
			return get_connect_session_name(this->to_mac.data(), this->to_port, this->from_mac.data(), this->from_port);
		}
	}
	return std::string("");
}

SessionMode Session::get_session_mode(){
	return this->mode;
}

SessionPhase Session::get_session_phase(){
	return this->phase;
}

void Session::close_socket(){
	if (this->sock_fd != -1){
		native_close(this->sock_fd);
		this->sock_fd = -1;
	}
}

std::string Session::get_client_addr(){
	return this->client_addr;
}

std::string Session::get_from_mac(){
	return from_mac;
}

std::string Session::get_to_mac(){
	return to_mac;
}

uint16_t Session::get_from_port(){
	return from_port;
}

uint16_t Session::get_to_port(){
	return to_port;
}

int Session::get_client_port(){
	return client_port;
}

}
