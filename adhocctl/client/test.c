#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <time.h>

#include "adhocctl.h"

void sleep_ms(int ms){
	struct timespec sleep_time = {
		.tv_sec = ms / 1000,
		.tv_nsec = (ms % 1000) * 1000000,
	};
	nanosleep(&sleep_time, NULL);
}

int main() {
	struct adhocctl_addr_v4 addr = {
		.ip = 0x0100007f,
		.port = 0xb06a,
	};

	char game_code[] = "ABCD12345";

	char nickname_a[128] = {0};
	sprintf(nickname_a, "nickname a");
	char mac_a[6];
	memset(mac_a, 0xa, 6);
	void *session_a = create_adhocctl_session_v4(&addr, 1, game_code, nickname_a, mac_a, 11);
	if (session_a == NULL){
		printf("%s: cannot create session a\n", __func__);
		exit(1);
	}

	char nickname_b[128] = {0};
	sprintf(nickname_b, "nickname b");
	char mac_b[6];
	memset(mac_b, 0xb, 6);
	void *session_b = create_adhocctl_session_v4(&addr, 1, game_code, nickname_b, mac_b, 11);
	if (session_b == NULL){
		printf("%s: cannot create session b\n", __func__);
		exit(1);
	}

	sleep_ms(600);

	char group_name[] = "abcd1234";
	enum adhocctl_call_status call_status = adhocctl_connect(session_a, group_name);
	if (call_status != ADHOCCTL_CALL_SUCCESS){
		printf("%s: adhocctl_connect failed\n", __func__);
		exit(1);
	}

	sleep_ms(100);

	struct adhocctl_event event = {0};
	adhocctl_get_event(session_a, &event);
	if (event.type != ADHOCCTL_EVENT_LEADER_MAC){
		printf("%s: expected event ADHOCCTL_EVENT_LEADER_MAC, got %d\n", __func__, event.type);
		exit(1);
	}
	if (memcmp(event.leader_mac.mac, mac_a, 6) != 0){
		printf("%s: bad leader mac during a joining\n", __func__);
		exit(1);
	}

	sleep_ms(100);

	call_status = adhocctl_scan(session_b);
	if (call_status != ADHOCCTL_CALL_SUCCESS){
		printf("%s: adhocctl_scan failed\n", __func__);
		exit(1);
	}

	sleep_ms(100);

	adhocctl_get_event(session_b, &event);
	if (event.type != ADHOCCTL_EVENT_SCAN){
		printf("%s: expected event ADHOCCTL_EVENT_SCAN, got %d\n", __func__, event.type);
		exit(1);
	}
	if (memcmp(event.scan.leader_mac, mac_a, 6) != 0){
		printf("%s: bad leader mac during scan\n", __func__);
		exit(1);
	}
	if (memcmp(event.scan.group_name, group_name, 8) != 0){
		printf("%s: bad group name during scan\n", __func__);
		exit(1);
	}

	adhocctl_get_event(session_b, &event);
	if (event.type != ADHOCCTL_EVENT_SCAN_COMPLETE){
		printf("%s: expected event ADHOCCTL_EVENT_SCAN_COMPLETE, got %d\n", __func__, event.type);
		exit(1);
	}

	call_status = adhocctl_connect(session_b, group_name);
	if (call_status != ADHOCCTL_CALL_SUCCESS){
		printf("%s: adhocctl_connect failed\n", __func__);
		exit(1);
	}

	sleep_ms(100);

	adhocctl_get_event(session_a, &event);
	if (event.type != ADHOCCTL_EVENT_CONNECT){
		printf("%s: expected event ADHOCCTL_EVENT_CONNECT, got %d\n", __func__, event.type);
		exit(1);
	}
	if (memcmp(event.connect.nickname, nickname_b, 128) != 0){
		printf("%s: bad nickname on b joining notification\n", __func__);
		exit(1);
	}
	if (memcmp(event.connect.mac, mac_b, 6) != 0){
		printf("%s: bad mac on b joining notification\n", __func__);
		exit(1);
	}

	adhocctl_get_event(session_b, &event);
	if (event.type != ADHOCCTL_EVENT_CONNECT){
		printf("%s: expected event ADHOCCTL_EVENT_CONNECT, got %d\n", __func__, event.type);
		exit(1);
	}
	if (memcmp(event.connect.nickname, nickname_a, 128) != 0){
		printf("%s: bad nickname on a already in group notification\n", __func__);
		exit(1);
	}
	if (memcmp(event.connect.mac, mac_a, 6) != 0){
		printf("%s: bad mac on a already in group notification\n", __func__);
		exit(1);
	}

	adhocctl_get_event(session_b, &event);
	if (event.type != ADHOCCTL_EVENT_LEADER_MAC){
		printf("%s: expected event ADHOCCTL_EVENT_LEADER_MAC, got %d\n", __func__, event.type);
		exit(1);
	}
	if (memcmp(event.leader_mac.mac, mac_a, 6) != 0){
		printf("%s: bad leader mac during b joining\n", __func__);
		exit(1);
	}

	char message_a[] = "hello from a";
	char message_b[] = "hello from b";

	call_status = adhocctl_chat(session_a, message_a);
	call_status = adhocctl_chat(session_b, message_b);

	sleep_ms(100);

	adhocctl_get_event(session_a, &event);
	if (event.type != ADHOCCTL_EVENT_CHAT){
		printf("%s: expected event ADHOCCTL_EVENT_CHAT, got %d\n", __func__, event.type);
		exit(1);
	}
	if (memcmp(event.chat.nickname, nickname_b, 128) != 0){
		printf("%s: bad nickname on message from b\n", __func__);
		exit(1);
	}
	if (strcmp(event.chat.message, message_b) != 0){
		printf("%s: bad message from b\n", __func__);
		exit(1);
	}

	adhocctl_get_event(session_b, &event);
	if (event.type != ADHOCCTL_EVENT_CHAT){
		printf("%s: expected event ADHOCCTL_EVENT_CHAT, got %d\n", __func__, event.type);
		exit(1);
	}
	if (memcmp(event.chat.nickname, nickname_a, 128) != 0){
		printf("%s: bad nickname on message from a\n", __func__);
		exit(1);
	}
	if (strcmp(event.chat.message, message_a) != 0){
		printf("%s: bad message from a\n", __func__);
		exit(1);
	}

	adhocctl_disconnect(session_a);

	sleep_ms(100);
	adhocctl_get_event(session_b, &event);
	if (event.type != ADHOCCTL_EVENT_DISCONNECT){
		printf("%s: expected event ADHOCCTL_EVENT_DISCONNECT, got %d\n", __func__, event.type);
		exit(1);
	}

	printf("%s: test ok\n", __func__);
}
