#pragma once

namespace aemu_postoffice_server {

class Semaphore{
	public:
		Semaphore();
		Semaphore(Semaphore &&from){
			sema_impl = from.sema_impl;
			from.sema_impl = nullptr;
		}
		~Semaphore();
		void acquire();
		void release();
	private:
		void *sema_impl;
};

}
