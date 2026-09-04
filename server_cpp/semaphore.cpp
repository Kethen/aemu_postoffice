#include "semaphore.h"

#include <semaphore>

namespace aemu_postoffice_server {

Semaphore::Semaphore(){
	std::counting_semaphore<65535> *sema = new std::counting_semaphore<65535>(0);
	sema_impl = sema;
}

Semaphore::~Semaphore(){
	if (sema_impl == nullptr){
		return;
	}
	std::counting_semaphore<65535> *sema = (std::counting_semaphore<65535> *)sema_impl;
	delete(sema);
}

void Semaphore::acquire(){
	std::counting_semaphore<65535> *sema = (std::counting_semaphore<65535> *)sema_impl;
	sema->acquire();
}

void Semaphore::release(){
	std::counting_semaphore<65535> *sema = (std::counting_semaphore<65535> *)sema_impl;
	sema->release();
}

}
