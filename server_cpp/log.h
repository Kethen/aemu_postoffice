#pragma once

namespace aemu_postoffice_server {

extern void (*LOG)(const char *format, ...);
extern void (*LOG_TS)(const char *format, ...);

}
