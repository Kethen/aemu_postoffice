#ifndef __MUTEX_IMPL_H
#define __MUTEX_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

void init_mutex();

void lock_sock_alloc_mutex();
void unlock_sock_alloc_mutex();

void lock_drain_mutex();
void unlock_drain_mutex();

void lock_enet_mutex();
void unlock_enet_mutex();

#ifdef __cplusplus
}
#endif

#endif
