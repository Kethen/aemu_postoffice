#include <stdarg.h>
#include <stdio.h>

#include <mutex>

namespace aemu_postoffice_server {

static std::mutex log_default_mutex;

void log_default(const char *format, ...){
	va_list args;
	va_start(args, format);

	char buf[2048] = {0};
	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	log_default_mutex.lock();
	fprintf(stdout, "%s", buf);
	log_default_mutex.unlock();
}

void (*LOG)(const char *format, ...) = log_default;

}
