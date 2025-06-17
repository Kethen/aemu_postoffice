#ifndef __POSTOFFICE_H
#define __POSTOFFICE_H

#ifdef __cplusplus
extern "C" {
#endif
int start_postoffice(int port, int max_threads, int max_pending_sessions, bool *stop_thread);
#ifdef __cplusplus
}
#endif

#endif
