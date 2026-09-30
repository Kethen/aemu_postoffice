#include "thread_impl.h"
#include "log_impl.h"

#include <stdlib.h>
#include <string.h>

#include <pspthreadman.h>

struct thread{
	int (*func)(void *arg, int arg_size);
	void *arg_copy;
	int arg_size;
	int ret;
	int thread_id;
};

static int thread_wrapper(unsigned int args, void *argp){
	struct thread *ctx = *(struct thread **)argp;
	ctx->ret = ctx->func(ctx->arg_copy, ctx->arg_size);
	return 0;
}

int partition_to_use();
void *thread_create(int (*func)(void *arg, int arg_size), void *arg, int arg_size){
	void *arg_copy = NULL;
	if (arg != NULL){
		arg_copy = malloc(arg_size);
		if (arg_copy == NULL){
			LOG("%s: failed allocating memory for arg copy\n", __func__);
			return NULL;
		}
	}
	memcpy(arg_copy, arg, arg_size);

	struct thread *ctx = malloc(sizeof(struct thread));
	if (ctx == NULL){
		LOG("%s: failed allocating memory for thread ctx\n", __func__);
		if (arg_copy != NULL)
			free(arg_copy);
		return NULL;
	}

	ctx->arg_copy = arg_copy;
	ctx->arg_size = arg_size;

	SceKernelThreadOptParam thread_param = {
		.size = sizeof(SceKernelThreadOptParam),
		.stackMpid = partition_to_use(),
	};

	int thread_id = sceKernelCreateThread("aemu_postoffice", thread_wrapper, 0x18, 1024 * 8, 0, &thread_param);
	if (thread_id < 0){
		LOG("%s: failed creating thread\n", __func__);
		if (arg_copy != NULL)
			free(arg_copy);
		free(ctx);
		return NULL;
	}

	ctx->thread_id = thread_id;

	int thread_start_status = sceKernelStartThread(thread_id, sizeof(ctx), &ctx);
	if (thread_start_status != 0){
		LOG("%s: failed starting thread\n", __func__);
		sceKernelDeleteThread(thread_id);
		if (arg_copy != NULL)
			free(arg_copy);
		free(ctx);
		return NULL;
	}

	return ctx;
}

int thread_join(void *thread_handle){
	struct thread *ctx = (struct thread*)thread_handle;
	sceKernelWaitThreadEnd(ctx->thread_id, NULL);
	sceKernelDeleteThread(ctx->thread_id);
	if (ctx->arg_copy != NULL)
		free(ctx->arg_copy);
	int ret = ctx->ret;
	free(ctx);
	return ret;
}
