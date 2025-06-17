#include <stdio.h>

#include <pthread.h>

FILE *log_file = NULL;
pthread_mutex_t log_mutex;

void init_logging()
{
	pthread_mutex_init(&log_mutex, NULL);
}
