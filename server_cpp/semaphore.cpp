#include "semaphore.h"

namespace aemu_postoffice_server {

void Semaphore::acquire(){
	this->sema.acquire();
}

void Semaphore::release(){
	this->sema.release();
}

}
