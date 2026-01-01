#include <stdio.h>

#include <pthread.h>

FILE *log_file = NULL;
pthread_mutex_t log_mutex;

#ifdef __cplusplus
extern "C" {
#endif

void init_logging()
{
	pthread_mutex_init(&log_mutex, NULL);
}

#ifdef __cplusplus
}
#endif
