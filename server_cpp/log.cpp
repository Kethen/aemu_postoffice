#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include <mutex>

#ifdef _WIN32
#define localtime_r(src, dst) localtime_s(dst, src)
#endif

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

void log_ts_default(const char *format, ...){
	va_list args;
	va_start(args, format);

	char buf[2048] = {0};

	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	time_t now;
	time(&now);
	struct tm lt;
	localtime_r(&now, &lt);
	char time_buf[128] = {0};
	strftime(time_buf, sizeof(time_buf) - 1, "%c", &lt);

	LOG("%s: %s", time_buf, buf);
}

void (*LOG_TS)(const char *format, ...) = log_ts_default;

}
