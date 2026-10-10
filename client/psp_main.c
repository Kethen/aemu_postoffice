#include <pspsdk.h>

#include <stdint.h>
#include <stdbool.h>

#include <pspsysmem.h>

#include "postoffice_client.h"
#include "log_impl.h"

#include "../ext/tinyalloc-master/tinyalloc.h"

#define MODULE_NAME "aemu_postoffice_client"

PSP_MODULE_INFO(MODULE_NAME, PSP_MODULE_USER + 6, 1, 4);

static SceUID heap_block = -1;
static SceUID enet_pump_thread = -1;
static SceLwMutexWorkarea malloc_mutex;

int has_high_mem();
int partition_to_use();

static bool enet_pump_stop = false;
static int enet_pump_func(unsigned int arg_size, void *arg){
	while (!enet_pump_stop){
		static const int target_frametime_us = 1000000 / 120;
		uint64_t begin = sceKernelGetSystemTimeWide();
		pump_enet_aemu_postoffice();
		uint64_t time_used_us = sceKernelGetSystemTimeWide() - begin;
		if (target_frametime_us > time_used_us){
			sceKernelDelayThread(target_frametime_us - time_used_us);
		}
	}
	return 0;
}

static void lock_malloc_mutex(){
	sceKernelLockLwMutex(&malloc_mutex, 1, NULL);
}

static void unlock_malloc_mutex(){
	sceKernelUnlockLwMutex(&malloc_mutex, 1);
}

void *malloc(int size){
	lock_malloc_mutex();
	void *ret = ta_alloc(size);
	unlock_malloc_mutex();
	return ret;
}

void free(void *block){
	lock_malloc_mutex();
	ta_free(block);
	unlock_malloc_mutex();
}

int module_start(SceSize args, void *argp){
	sceKernelCreateLwMutex(&malloc_mutex, "aemu_postoffice malloc mutex", 0, 0, NULL);

	if (has_high_mem()){
		static const int heap_size = 1024 * 512;
		heap_block = sceKernelAllocPartitionMemory(partition_to_use(), "postoffice enet heap", 4 /* high aligned */, heap_size, NULL);
		if (heap_block < 0){
			LOG("%s: failed allocating partition memory, not initializing enet\n", __func__);
			heap_block = -1;
			init_aemu_postoffice(false);
			return 0;
		}

		void *heap_block_head = sceKernelGetBlockHeadAddr(heap_block);

		ta_init(heap_block_head, (void *)((uint32_t)heap_block_head + (uint32_t)heap_size), 256, 16, 8);
		init_aemu_postoffice(true);

		enet_pump_stop = false;
		SceKernelThreadOptParam thread_opt = {
			.size = sizeof(SceKernelThreadOptParam),
			.stackMpid = partition_to_use()
		};
		enet_pump_thread = sceKernelCreateThread("aemu_postoffice enet pumping", enet_pump_func, 40, 1024 * 4, 0, &thread_opt);
		if (enet_pump_thread < 0){
			LOG("%s: failed creating enet thread, 0x%x, pumping will not be carried out!\n", __func__, enet_pump_thread);
			enet_pump_thread = -1;
			return 0;
		} else {
			sceKernelStartThread(enet_pump_thread, 0, NULL);
		}

		return 0;
	}
	init_aemu_postoffice(false);
	return 0;
}

int module_stop(SceSize args, void *argp){
	if (enet_pump_thread != -1){
		enet_pump_stop = true;
		sceKernelWaitThreadEnd(enet_pump_thread, NULL);
		sceKernelDeleteThread(enet_pump_thread);
		enet_pump_thread = -1;
	}

	deinit_aemu_postoffice();

	if (heap_block != -1){
		sceKernelFreePartitionMemory(heap_block);
		heap_block = -1;
	}

	sceKernelDeleteLwMutex(&malloc_mutex);

	return 0;
}

uint8_t *memcpy(uint8_t *dst, const uint8_t *src, int size){
	for(int i = 0;i < size;i++){
		dst[i] = src[i];
	}
	return dst;
}

uint8_t *memset(uint8_t *dst, int val, int size){
	for(int i = 0;i < size;i++){
		dst[i] = val;
	}
	return dst;
}
