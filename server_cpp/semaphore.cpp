// SPDX-License-Identifier: GPL-3.0-only
#include "semaphore.h"

#include <condition_variable>
#include <mutex>

namespace aemu_postoffice_server {

// C++17 replacement for std::counting_semaphore from C++20.
struct SemaphoreImpl{
	std::mutex mutex;
	std::condition_variable cond;
	unsigned int count = 0;
};

Semaphore::Semaphore(){
	sema_impl = new SemaphoreImpl();
}

Semaphore::~Semaphore(){
	if (sema_impl == nullptr){
		return;
	}
	delete (SemaphoreImpl *)sema_impl;
}

void Semaphore::acquire(){
	SemaphoreImpl *sema = (SemaphoreImpl *)sema_impl;
	std::unique_lock<std::mutex> lock(sema->mutex);
	sema->cond.wait(lock, [sema]{ return sema->count > 0; });
	sema->count--;
}

void Semaphore::release(){
	SemaphoreImpl *sema = (SemaphoreImpl *)sema_impl;
	{
		std::lock_guard<std::mutex> lock(sema->mutex);
		sema->count++;
	}
	sema->cond.notify_one();
}

}
