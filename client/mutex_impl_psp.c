#include <pspthreadman.h>

static SceLwMutexWorkarea sock_alloc_mutex;
void init_sock_alloc_mutex(){
	sceKernelCreateLwMutex(&sock_alloc_mutex, "aemu_postoffice_client", 0, 0, NULL);
}
void lock_sock_alloc_mutex(){
	sceKernelLockLwMutex(&sock_alloc_mutex, 1, 0);
}
void unlock_sock_alloc_mutex(){
	sceKernelUnlockLwMutex(&sock_alloc_mutex, 1);
}
