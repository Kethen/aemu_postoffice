#ifndef __LOG_H
#define __LOG_H

#include <stdio.h>
#include <pthread.h>

#define LOG_FILE_PATH "./aemu_postoffice.log"

extern FILE *log_file;
extern pthread_mutex_t log_mutex;

#ifdef __cplusplus
extern "C" {
#endif
void init_logging();
#ifdef __cplusplus
}
#endif


#define LOG(...) { \
	pthread_mutex_lock(&log_mutex); \
	if (log_file == NULL){ \
		log_file = fopen(LOG_FILE_PATH, "wb"); \
	} \
	if (log_file != NULL){ \
		fprintf(log_file, __VA_ARGS__); \
		fclose(log_file); \
		log_file = NULL; \
	} \
	fprintf(stderr, __VA_ARGS__); \
	pthread_mutex_unlock(&log_mutex); \
}

#endif
