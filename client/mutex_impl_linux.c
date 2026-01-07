#include <pthread.h>
#include <time.h>

static pthread_mutex_t sock_alloc_mutex;
void init_sock_alloc_mutex(){
	pthread_mutex_init(&sock_alloc_mutex, NULL);
}
void lock_sock_alloc_mutex(){
	pthread_mutex_lock(&sock_alloc_mutex);
}
void unlock_sock_alloc_mutex(){
	pthread_mutex_unlock(&sock_alloc_mutex);
}

void delay(int ms){
	const struct timespec duration = {
		.tv_sec = 0,
		.tv_nsec = ms * 1000000,
	};
	nanosleep(&duration, NULL);
}
