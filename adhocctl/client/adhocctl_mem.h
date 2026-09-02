#ifndef __ADHOCCTL_MEM_H
#define __ADHOCCTL_MEM_H

#include "stdbool.h"

struct session {
	bool in_use;
	char game_code[9];
	char nickname[128];
	char mac[6];
	int sock_fd;
	int protocol_revision;
};

extern const int *num_sessions;
extern struct session *sessions;

#endif
