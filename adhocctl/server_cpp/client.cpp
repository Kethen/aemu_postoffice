#include <stdlib.h>
#include <string.h>

#include "client.h"
#include "log.h"
#include "../../server_cpp/native_socket.h"
#include "common.h"

#include "../packets_v1.h"

using namespace aemu_postoffice_server;

namespace aemu_postoffice_adhocctl_server {

Client::Client(int sock_fd, std::string ip, uint16_t port, std::string socket_name, int protocol_revision, aemu_postoffice_server::Config *config){
	this->sock_fd = sock_fd;
	this->ip = ip;
	this->port = port;
	this->socket_name = socket_name;
	this->protocol_revision = protocol_revision;
	this->logged_in = false;
	this->config = config;

	this->game_code = "";
	this->group = "";

	this->create_time = std::chrono::high_resolution_clock::now();
	this->last_seen = std::chrono::high_resolution_clock::now();
}

void Client::close_socket(){
	native_close(this->sock_fd);
}

Client::~Client(){

}

static bool client_sent_too_much(const std::string &recv_buf, aemu_postoffice_server::Config *config, Client *client){
	if (recv_buf.length() > config->adhocctl_data_queue_size_limit_byte){
		LOG("%s: client %s %s is sending too much data\n", __func__, mac_bytes_to_mac_string(client->get_mac()).c_str(), client->get_socket_name().c_str());
		return true;
	}
	return false;
}

static ServerToClientOpQueueStatus check_send_queue_size(const std::string &send_buf, aemu_postoffice_server::Config *config, Client *client){
	if (send_buf.length() > config->adhocctl_data_queue_size_limit_byte){
		LOG("%s: client %s %s is not receiving data timely\n", __func__, mac_bytes_to_mac_string(client->get_mac()).c_str(), client->get_socket_name().c_str());
		return ServerToClientOpQueueStatus::OVERFLOW;
	}
	return ServerToClientOpQueueStatus::SUCCESS;
}

static void connect_ack_v1(std::string &send_buf, std::string group_mac){
	SceNetAdhocctlConnectBSSIDPacketS2C packet = {0};
	packet.base.opcode = OPCODE_CONNECT_BSSID;
	memcpy(packet.mac.data, group_mac.data(), 6);
	send_buf.append((char *)&packet, sizeof(packet));
}

ServerToClientOpQueueStatus Client::connect_ack(std::string group_mac){
	switch(this->protocol_revision){
		case 1:
			connect_ack_v1(this->send_buf, group_mac);
			break;
		default:
			LOG("%s: bad protocol revision %d, debug this\n", __func__, this->protocol_revision);
			exit(1);
	}
	return check_send_queue_size(this->send_buf, this->config, this);
}

static void disconnect_notify_v1(std::string &send_buf, uint32_t ip){
	SceNetAdhocctlDisconnectPacketS2C packet = {0};
	packet.base.opcode = OPCODE_DISCONNECT;
	packet.ip = ip;
	send_buf.append((char *)&packet, sizeof(packet));
}

ServerToClientOpQueueStatus Client::disconnect_notify(Client *peer){
	switch(this->protocol_revision){
		case 1:
			disconnect_notify_v1(this->send_buf, peer->id);
			break;
		default:
			LOG("%s: bad protocol revision %d, debug this\n", __func__, this->protocol_revision);
			exit(1);
	}
	return check_send_queue_size(this->send_buf, this->config, this);
}

static void chat_v1(std::string &send_buf, std::string nickname, std::string msg){
	SceNetAdhocctlChatPacketS2C packet = {0};
	packet.base.base.opcode = OPCODE_CHAT;
	strncpy(packet.base.message, msg.c_str(), sizeof(packet.base.message) - 1);
	strncpy((char *)packet.name.data, nickname.c_str(), sizeof(packet.name.data) - 1);
	send_buf.append((char *)&packet, sizeof(packet));
}

ServerToClientOpQueueStatus Client::chat(std::string nickname, std::string msg){
	switch(this->protocol_revision){
		case 1:
			chat_v1(this->send_buf, nickname, msg);
			break;
		default:
			LOG("%s: bad protocol revision %d, debug this\n", __func__, this->protocol_revision);
			exit(1);
	}
	return check_send_queue_size(this->send_buf, this->config, this);
}

static void scan_result_v1(std::string &send_buf, std::string group_name, std::string leader_mac){
	SceNetAdhocctlScanPacketS2C packet = {0};
	packet.base.opcode = OPCODE_SCAN;
	memcpy(packet.group.data, group_name.data(), group_name.length() > sizeof(packet.group.data) ? sizeof(packet.group.data) : group_name.length());
	memcpy(packet.mac.data, leader_mac.data(), 6);
	send_buf.append((char *)&packet, sizeof(packet));
}

ServerToClientOpQueueStatus Client::scan_result(std::string group_name, std::string leader_mac){
	switch(this->protocol_revision){
		case 1:
			scan_result_v1(this->send_buf, group_name, leader_mac);
			break;
		default:
			LOG("%s: bad protocol revision %d, debug this\n", __func__, this->protocol_revision);
			exit(1);
	}
	return check_send_queue_size(this->send_buf, this->config, this);
}

static void scan_complete_v1(std::string &send_buf){
	SceNetAdhocctlPacketBase packet = {0};
	packet.opcode = OPCODE_SCAN_COMPLETE;
	send_buf.append((char *)&packet, sizeof(packet));
}

ServerToClientOpQueueStatus Client::scan_complete(){
	switch(this->protocol_revision){
		case 1:
			scan_complete_v1(this->send_buf);
			break;
		default:
			LOG("%s: bad protocol revision %d, debug this\n", __func__, this->protocol_revision);
			exit(1);
	}
	return check_send_queue_size(this->send_buf, this->config, this);
}

static void connect_notify_v1(std::string &send_buf, std::string nickname, std::string mac, uint32_t ip){
	SceNetAdhocctlConnectPacketS2C packet = {0};
	packet.base.opcode = OPCODE_CONNECT;
	memcpy(packet.name.data, nickname.data(), nickname.length() > sizeof(packet.name.data) ? sizeof(packet.name.data) : nickname.length());
	memcpy(packet.mac.data, mac.data(), 6);
	packet.ip = ip;
	send_buf.append((char *)&packet, sizeof(packet));
}

ServerToClientOpQueueStatus Client::connect_notify(Client *peer){
	switch(this->protocol_revision){
		case 1:
			connect_notify_v1(this->send_buf, peer->get_nickname(), peer->get_mac(), peer->id);
			break;
		default:
			LOG("%s: bad protocol revision %d, debug this\n", __func__, this->protocol_revision);
			exit(1);
	}
	return check_send_queue_size(this->send_buf, this->config, this);
}

ClientPumpStatus Client::process_recv_buf_v1(){
	bool processed_packet = false;
	while(true){
		if (recv_buf.length() < sizeof(SceNetAdhocctlPacketBase)){
			if (processed_packet){
				last_seen = std::chrono::high_resolution_clock::now();
			}
			return ClientPumpStatus::SUCCESS;
		}

		const SceNetAdhocctlPacketBase *packet_base = (SceNetAdhocctlPacketBase *)recv_buf.data();
		int packet_size = 0;
		switch(packet_base->opcode){
			case OPCODE_LOGIN:
				packet_size = sizeof(SceNetAdhocctlLoginPacketC2S);
				break;
			case OPCODE_PING:
				packet_size = sizeof(SceNetAdhocctlPacketBase);
				break;
			case OPCODE_CONNECT:
				if (!logged_in){
					LOG("%s: client %s sending OPCODE_CONNECT before logging in\n", __func__, socket_name.c_str());
					return ClientPumpStatus::ERROR;
				}
				packet_size = sizeof(SceNetAdhocctlConnectPacketC2S);
				break;
			case OPCODE_DISCONNECT:
				if (!logged_in){
					LOG("%s: client %s sending OPCODE_DISCONNECT before logging in\n", __func__, socket_name.c_str());
					return ClientPumpStatus::ERROR;
				}
				packet_size = sizeof(SceNetAdhocctlPacketBase);
				break;
			case OPCODE_SCAN:
				if (!logged_in){
					LOG("%s: client %s sending OPCODE_SCAN before logging in\n", __func__, socket_name.c_str());
					return ClientPumpStatus::ERROR;
				}
				packet_size = sizeof(SceNetAdhocctlPacketBase);
				break;
			case OPCODE_CHAT:
				if (!logged_in){
					LOG("%s: client %s sending OPCODE_CHAT before logging in\n", __func__, socket_name.c_str());
					return ClientPumpStatus::ERROR;
				}
				packet_size = sizeof(SceNetAdhocctlChatPacketC2S);
				break;
			default:
				LOG("%s: client %s sent invalid opcode %d\n", __func__,socket_name.c_str(), packet_base->opcode);
				return ClientPumpStatus::ERROR;
		}

		if (recv_buf.length() < packet_size){
			if (processed_packet){
				last_seen = std::chrono::high_resolution_clock::now();
			}
			return ClientPumpStatus::SUCCESS;
		}

		processed_packet = true;
		switch(packet_base->opcode){
			case OPCODE_LOGIN:{
				const SceNetAdhocctlLoginPacketC2S *packet = (SceNetAdhocctlLoginPacketC2S *)recv_buf.data();
				mac = std::string((char *)packet->mac.data, 6);
				nickname = std::string((char *)packet->name.data, sizeof(packet->name.data));
				game_code = std::string((char *)packet->game.data, sizeof(packet->game.data));
				nickname.push_back('\0');
				game_code.push_back('\0');
				channel = V1_PROTOCOL_DEFAULT_CHANNEL;
				logged_in = true;

				break;
			}
			case OPCODE_PING:{
				// no op, last seen will be updated later
				break;
			}
			case OPCODE_CONNECT:{
				const SceNetAdhocctlConnectPacketC2S *packet = (SceNetAdhocctlConnectPacketC2S *)recv_buf.data();
				client_op op;
				op.mac = mac;
				op.op = ClientOp::CONNECT;
				op.connect.group = std::string((char *)packet->group.data, sizeof(packet->group.data));
				op.connect.group.push_back('\0');
				// v1 protocol has no channel
				op.connect.channel = channel;
				client_ops.push_back(op);
				break;
			}
			case OPCODE_DISCONNECT:{
				client_op op;
				op.mac = mac;
				op.op = ClientOp::DISCONNECT;
				op.disconnect.channel = channel;
				client_ops.push_back(op);
				break;
			}
			case OPCODE_SCAN:{
				client_op op;
				op.mac = mac;
				op.op = ClientOp::SCAN;
				client_ops.push_back(op);
				break;
			}
			case OPCODE_CHAT:{
				const SceNetAdhocctlChatPacketC2S *packet = (SceNetAdhocctlChatPacketC2S *)recv_buf.data();
				client_op op;
				op.mac = mac;
				op.op = ClientOp::CHAT;
				char buf[sizeof(packet->message) + 1] = {0};
				strncpy(buf, packet->message, sizeof(packet->message));
				op.chat.msg = std::string(buf);
				client_ops.push_back(op);
				break;
			}
			default:
				LOG("%s: unreachable codepath, debug this\n", __func__);
				exit(1);
		}

		recv_buf.erase(0, packet_size);
	}
}

ClientPumpStatus Client::pump_from_client(){
	if (!logged_in){
		if ((std::chrono::high_resolution_clock::now() - create_time) / std::chrono::seconds(1) > 5){
			LOG("%s: pending client %s has timed out\n", __func__, get_socket_name().c_str());
			return ClientPumpStatus::TIMEDOUT;
		}
	}

	if ((std::chrono::high_resolution_clock::now() - last_seen) / std::chrono::milliseconds(1) > config->adhocctl_timeout_ms){
		LOG("%s: client %s %s has timed out\n", __func__, get_socket_name().c_str(), mac_bytes_to_mac_string(mac).c_str());
		return ClientPumpStatus::TIMEDOUT;
	}

	// drain kernel buffer into our buffer
	while(true){
		char recv_buf[4096];
		int recv_status = native_recv(sock_fd, recv_buf, sizeof(recv_buf));
		if (recv_status == 0){
			LOG("%s: client %s %s has disconnected\n", __func__, get_socket_name().c_str(), mac_bytes_to_mac_string(mac).c_str());
			return ClientPumpStatus::DISCONNECT;
		}
		if (recv_status == -1){
			int error = native_get_last_socket_error();
			if (native_error_is_would_block(error)){
				break;
			}
			LOG("%s: client %s %s has errored 0x%x\n", __func__, get_socket_name().c_str(), mac_bytes_to_mac_string(mac).c_str(), error);
			return ClientPumpStatus::ERROR;
		}
		// we have data otherwise
		this->recv_buf.append(recv_buf, recv_status);
	}

	if (client_sent_too_much(recv_buf, config, this)){
		return ClientPumpStatus::OVERFLOW;
	}

	// process packets into op list
	switch(this->protocol_revision){
		case 1:
			return process_recv_buf_v1();
			// TODO v2 protocol's login should handle some kind of auth
		default:
			LOG("%s: bad protocol revision %d, debug this\n", __func__, this->protocol_revision);
			exit(1);
			return ClientPumpStatus::SUCCESS;
	}
}

ClientPumpStatus Client::pump_to_client(){
	while (true){
		if (send_buf.length() == 0){
			return ClientPumpStatus::SUCCESS;
		}

		int send_status = native_send(sock_fd, send_buf.data(), send_buf.length());
		if (send_status == -1){
			int err = native_get_last_socket_error();
			if (native_error_is_would_block(err)){
				return ClientPumpStatus::SUCCESS;
			}
			LOG("%s: failed sending to client, 0x%x\n", __func__, err);
			return ClientPumpStatus::ERROR;
		}

		send_buf.erase(0, send_status);
	}
}

std::string Client::get_ip(){
	return ip;
}

std::string Client::get_socket_name(){
	return socket_name;
}

std::string Client::get_nickname(){
	return nickname;
}

bool Client::is_logged_in(){
	return logged_in;
}

std::string Client::get_mac(){
	return mac;
}

int Client::get_protocol_revision(){
	return protocol_revision;
}

int Client::get_channel(){
	return channel;
}

void Client::get_client_ops(std::vector<client_op> &container){
	std::swap(client_ops, container);
	client_ops.clear();
}

}

