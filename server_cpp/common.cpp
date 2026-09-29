#include <stdio.h>
#include <stdint.h>

#include <pthread.h>

#include <string>

namespace aemu_postoffice_server {

std::string mac_bytes_to_mac_string(std::string mac){
	char buf[128] = {0};
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", (uint8_t)mac.data()[0], (uint8_t)mac.data()[1], (uint8_t)mac.data()[2], (uint8_t)mac.data()[3], (uint8_t)mac.data()[4], (uint8_t)mac.data()[5]);
	return std::string(buf);
}

void set_thread_name(std::string name){
	#if __unix__
	pthread_t tid = pthread_self();
	pthread_setname_np(tid, name.c_str());
	#else
	// hm, what do
	#endif
}

}
