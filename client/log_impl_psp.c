// SPDX-License-Identifier: GPL-3.0-only
int printk(const char *format, ...);
int (*log_func)(const char *format, ...) = printk;
