#include "adhocctl_mem.h"

#define NUM_SESSIONS 8

static int _num_sessions = NUM_SESSIONS;
const int *num_sessions = &_num_sessions;
static struct session _sessions[NUM_SESSIONS];
struct session *sessions = _sessions;
