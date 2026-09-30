#include <mutex>

extern "C" {

void init_mutex(){
}

static std::mutex sock_alloc_mutex;
void lock_sock_alloc_mutex(){
	sock_alloc_mutex.lock();
}
void unlock_sock_alloc_mutex(){
	sock_alloc_mutex.unlock();
}

static std::mutex drain_mutex;
void lock_drain_mutex(){
	drain_mutex.lock();
}
void unlock_drain_mutex(){
	drain_mutex.unlock();
}

static std::mutex enet_mutex;
void lock_enet_mutex(){
	enet_mutex.lock();
}
void unlock_enet_mutex(){
	enet_mutex.unlock();
}

}
