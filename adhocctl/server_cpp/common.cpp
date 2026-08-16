#include <stdio.h>
#include <stdint.h>

#include <string>

std::string mac_bytes_to_mac_string(std::string mac){
	char buf[128] = {0};
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", (uint8_t)mac.data()[0], (uint8_t)mac.data()[1], (uint8_t)mac.data()[2], (uint8_t)mac.data()[3], (uint8_t)mac.data()[4], (uint8_t)mac.data()[5]);
	return std::string(buf);
}
