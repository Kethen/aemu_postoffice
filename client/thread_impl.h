#ifndef __THREAD_H
#define __THREAD_H

#ifdef __cplusplus
extern "C" {
#endif

void *thread_create(int (*func)(void *arg, int arg_size), void *arg, int arg_size);
int thread_join(void *thread_handle);

#ifdef __cplusplus
}
#endif

#endif
