#ifndef __LOG_PSP_H
#define __LOG_PSP_H

int printk(char *fmt, ...);

#define LOG(...){ \
	printk(__VA_ARGS__); \
}

#endif
