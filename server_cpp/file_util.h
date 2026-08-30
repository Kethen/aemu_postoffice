#pragma once

#include <stdio.h>

#include <string>

namespace aemu_postoffice_server {

long get_file_size(FILE *file);
std::string read_all_to_string(FILE *file);
std::string read_file_to_string(std::string path);

}
