// SPDX-License-Identifier: GPL-3.0-only
#include <pspthreadman.h>

void delay(int ms){
	sceKernelDelayThread(ms * 1000);
}
