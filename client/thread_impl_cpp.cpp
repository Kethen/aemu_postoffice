#include <thread>

#include <string.h>
#include <stdlib.h>

#include "log_impl.h"
#include "thread_impl.h"

extern "C" {

struct thread{
	void *arg_copy;
	int arg_size;
	int ret;
	std::thread *thread;
};

void *thread_create(int (*func)(void *arg, int arg_size), void *arg, int arg_size){
	void *arg_copy = malloc(arg_size);
	if (arg == NULL){
		LOG("%s: failed allocating memory for arg copy\n", __func__);
		return NULL;
	}
	memcpy(arg_copy, arg, arg_size);

	struct thread *ctx = new struct thread();

	ctx->arg_copy = arg_copy;
	ctx->arg_size = arg_size;

	ctx->thread = new std::thread([ctx, func] {
		ctx->ret = func(ctx->arg_copy, ctx->arg_size);
	});

	return ctx;
}

int thread_join(void *thread_handle){
	struct thread *ctx = (struct thread *)thread_handle;
	ctx->thread->join();
	delete ctx->thread;
	free(ctx->arg_copy);
	int ret = ctx->ret;
	delete ctx;
	return ret;
}

}
