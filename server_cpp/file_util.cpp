#include <stdlib.h>

#include "log.h"
#include "file_util.h"

namespace aemu_postoffice_server {

long get_file_size(FILE *file){
	long read_head = ftell(file);
	if (read_head == -1){
		LOG("%s: initial ftell failed\n", __func__);
		return -1;
	}

	int seek_status = fseek(file, 0, SEEK_END);
	if (seek_status == -1){
		LOG("%s: end fseek failed\n", __func__);
		return -1;
	}

	long size = ftell(file);
	if (size == -1){
		LOG("%s: size ftell failed\n", __func__);
		return -1;
	}

	seek_status = fseek(file, read_head, SEEK_SET);
	if (seek_status == -1){
		LOG("%s: read head reset failed\n", __func__);
		return -1;
	}

	return size;
}

std::string read_all_to_string(FILE *file){
	long read_head = ftell(file);
	if (read_head == -1){
		LOG("%s: initial ftell failed\n", __func__);
		return std::string("");
	}

	int seek_status = fseek(file, 0, SEEK_SET);
	if (seek_status == -1){
		LOG("%s: rewind failed\n", __func__);
		return std::string("");
	}

	long file_size = get_file_size(file);
	if (file_size == -1){
		LOG("%s: failed getting file size\n", __func__);
		return std::string("");
	}

	char *buf = (char *)malloc(file_size);
	if (buf == NULL){
		LOG("%s: failed allocating file read buffer\n", __func__);
		return std::string("");
	}

	int read_status = fread(buf, file_size, 1, file);
	if (read_status != 1){
		LOG("%s: fread failed\n", __func__);
		free(buf);
		return std::string("");
	}

	std::string ret(buf, file_size);
	free(buf);

	seek_status = fseek(file, read_head, SEEK_SET);
	if (seek_status == -1){
		LOG("%s: read head reset failed\n", __func__);
		return std::string("");
	}

	return ret;
}

std::string read_file_to_string(std::string path){
	FILE *file = fopen(path.c_str(), "rb");
	if (file == NULL){
		LOG("%s: failed opening file %s\n", __func__, path.c_str());
		return std::string("");
	}

	std::string ret = read_all_to_string(file);
	return ret;
}

}
