#pragma once

#include <string>

namespace aemu_postoffice_server {

class Buffer{
	public:
		Buffer(int size);
		~Buffer();
		int get_size();
		char *get_buf();

	private:
		char *buf;
		int size;
};

std::string mac_bytes_to_mac_string(std::string mac);
void set_thread_name(std::string name);

}
