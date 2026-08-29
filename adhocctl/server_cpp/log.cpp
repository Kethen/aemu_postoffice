#include <stdarg.h>
#include <stdio.h>

#include <mutex>

namespace aemu_postoffice_adhocctl_server {

std::mutex log_default_mutex;
void log_default(const char *format, ...){
	va_list args;
	va_start(args, format);

	char buf[2048] = {0};
	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	{
		const std::lock_guard<std::mutex> lock(log_default_mutex);
		fprintf(stdout, "%s", buf);
	}
}

void (*LOG)(const char *format, ...) = log_default;

}
