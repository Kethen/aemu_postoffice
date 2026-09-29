#pragma once

#include <string>

namespace aemu_postoffice_server {

std::string mac_bytes_to_mac_string(std::string mac);
void set_thread_name(std::string name);

}
