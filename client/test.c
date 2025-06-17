#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include "postoffice_client.h"

#define LOG(...) { \
	fprintf(stderr, __VA_ARGS__); \
}

void test_pdp(){
	struct in_addr local_addr = {
		.s_addr = htonl(INADDR_LOOPBACK)
	};
	static const char pdp_mac_a[6] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
	static const char pdp_mac_b[6] = {0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33};
	static const char pdp_mac_c[6] = {0xcc, 0xdd, 0xee, 0x11, 0x22, 0x33};
	static const int port_a = 12345;
	static const int port_b = 23456;
	static const int port_c = 34567;

	void *pdp_handle_a_replace = pdp_create_v4(local_addr, 27313, pdp_mac_a, port_a);
	if (pdp_handle_a_replace == NULL){
		LOG("%s: failed creating pdp socket\n", __func__);
		exit(1);
	}

	// just so we know the last socket is the one gets replaced
	sleep(1);

	void *pdp_handle_a = pdp_create_v4(local_addr, 27313, pdp_mac_a, port_a);
	
	if (pdp_handle_a == NULL){
		LOG("%s: failed creating pdp socket\n", __func__);
		exit(1);
	}

	sleep(1);
	pdp_delete(pdp_handle_a_replace);

	void *pdp_handle_b = pdp_create_v4(local_addr, 27313, pdp_mac_b, port_b);
	if (pdp_handle_b == NULL){
		LOG("%s: failed creating pdp socket\n", __func__);
		exit(1);
	}
	void *pdp_handle_c = pdp_create_v4(local_addr, 27313, pdp_mac_c, port_c);
	if (pdp_handle_c == NULL){
		LOG("%s: failed creating pdp socket\n", __func__);
		exit(1);
	}

	sleep(1);

	char test_data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	int send_status = pdp_send(pdp_handle_a, pdp_mac_b, port_b, test_data, sizeof(test_data), false);
	if (send_status != 0){
		LOG("%s: failed sending pdp packet from a to b, %d\n", __func__, send_status);
		exit(1);
	}

	send_status = pdp_send(pdp_handle_b, pdp_mac_c, port_c, test_data, sizeof(test_data), false);
	if (send_status != 0){
		LOG("%s: failed sending pdp packet from b to c, %d\n", __func__, send_status);
		exit(1);
	}

	char recv_buf[sizeof(test_data)];
	char incoming_mac[6];
	int incoming_port;
	int len = sizeof(recv_buf);
	int recv_status = pdp_recv(pdp_handle_b, incoming_mac, &incoming_port, recv_buf, &len, false);
	if (recv_status != 0){
		LOG("%s: receive failed from a to b, %d\n", __func__, recv_status);
		exit(1);
	}

	if (len != sizeof(recv_buf)){
		LOG("%s: bad length of received data from a to b\n", __func__);
		exit(1);
	}

	if (memcmp(incoming_mac, pdp_mac_a, 6) != 0){
		LOG("%s: bad mac address from a to b\n", __func__);
		exit(1);
	}

	if (incoming_port != port_a){
		LOG("%s: bad incoming port %d from a to b, expected %d\n", __func__, incoming_port, port_a);
		exit(1);
	}

	if (memcmp(test_data, recv_buf, sizeof(test_data)) != 0){
		LOG("%s: bad data received from a to b:\n", __func__);
		for(int i = 0;i < sizeof(test_data);i++){
			LOG("%d ", recv_buf[i]);
		}
		LOG("\n");
		exit(1);
	}

	
	len = sizeof(recv_buf);
	recv_status = pdp_recv(pdp_handle_c, incoming_mac, &incoming_port, recv_buf, &len, false);
	if (recv_status != 0){
		LOG("%s: receive failed from b to c, %d\n", __func__, recv_status);
		exit(1);
	}

	if (len != sizeof(recv_buf)){
		LOG("%s: bad length of received data from b to c\n", __func__);
		exit(1);
	}

	if (memcmp(incoming_mac, pdp_mac_b, 6) != 0){
		LOG("%s: bad mac address from b to c\n", __func__);
		exit(1);
	}

	if (incoming_port != port_b){
		LOG("%s: bad incoming port %d from b to c, expected %d\n", __func__, incoming_port, port_b);
		exit(1);
	}

	if (memcmp(test_data, recv_buf, sizeof(test_data)) != 0){
		LOG("%s: bad data received from b to c:\n", __func__);
		for(int i = 0;i < sizeof(test_data);i++){
			LOG("%d ", recv_buf[i]);
		}
		LOG("\n");
		exit(1);
	}

	sleep(1);

	send_status = pdp_send(pdp_handle_a, pdp_mac_c, port_c, test_data, sizeof(test_data), false);
	if (send_status != 0){
		LOG("%s: failed sending pdp packet from a to c, %d\n", __func__, send_status);
		exit(1);
	}

	len = sizeof(recv_buf);
	recv_status = pdp_recv(pdp_handle_c, incoming_mac, &incoming_port, recv_buf, &len, false);
	if (recv_status != 0){
		LOG("%s: receive failed from a to c, %d\n", __func__, recv_status);
		exit(1);
	}

	if (len != sizeof(recv_buf)){
		LOG("%s: bad length of received data from a to c\n", __func__);
		exit(1);
	}

	if (memcmp(incoming_mac, pdp_mac_a, 6) != 0){
		LOG("%s: bad mac address from a to c\n", __func__);
		exit(1);
	}

	if (incoming_port != port_a){
		LOG("%s: bad incoming port %d from a to c, expected %d\n", __func__, incoming_port, port_a);
		exit(1);
	}

	if (memcmp(test_data, recv_buf, sizeof(test_data)) != 0){
		LOG("%s: bad data received from a to c:\n", __func__);
		for(int i = 0;i < sizeof(test_data);i++){
			LOG("%d ", recv_buf[i]);
		}
		LOG("\n");
		exit(1);
	}

	len = sizeof(recv_buf);
	recv_status = pdp_recv(pdp_handle_c, incoming_mac, &incoming_port, recv_buf, &len, true);
	if (recv_status != AEMU_POSTOFFICE_CLIENT_SESSION_WOULD_BLOCK){
		LOG("%s: expected would block status for recv, got %d instead\n", __func__, recv_status);
		exit(1);
	}

	send_status = pdp_send(pdp_handle_c, pdp_mac_a, port_a, test_data, sizeof(test_data), true);
	if (send_status != 0){
		LOG("%s: failed sending pdp packet from c to a, %d\n", __func__, send_status);
		exit(1);
	}

	sleep(1);

	len = sizeof(recv_buf);
	recv_status = pdp_recv(pdp_handle_a, incoming_mac, &incoming_port, recv_buf, &len, true);
	if (recv_status != 0){
		LOG("%s: receive failed from c to a, %d\n", __func__, recv_status);
		exit(1);
	}

	if (len != sizeof(recv_buf)){
		LOG("%s: bad length of received data from c to a\n", __func__);
		exit(1);
	}

	if (memcmp(incoming_mac, pdp_mac_c, 6) != 0){
		LOG("%s: bad mac address from c to a\n", __func__);
		exit(1);
	}

	if (incoming_port != port_c){
		LOG("%s: bad incoming port %d from c to a, expected %d\n", __func__, incoming_port, port_c);
		exit(1);
	}

	if (memcmp(test_data, recv_buf, sizeof(test_data)) != 0){
		LOG("%s: bad data received from c to a:\n", __func__);
		for(int i = 0;i < sizeof(test_data);i++){
			LOG("%d ", recv_buf[i]);
		}
		LOG("\n");
		exit(1);
	}

	pdp_delete(pdp_handle_a);
	pdp_delete(pdp_handle_b);
	pdp_delete(pdp_handle_c);
}

int main(){
	test_pdp();
	LOG("%s: test ok\n", __func__);
	return 0;
}
