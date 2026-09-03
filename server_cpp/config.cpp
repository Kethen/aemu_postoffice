#include "config.h"
#include "file_util.h"
#include "log.h"

#include "../ext/json/json.hpp"

#define STR(s) #s

namespace aemu_postoffice_server {

bool parse_config_from_json(std::string path, struct config &out){
	std::string raw_json = read_file_to_string(path);
	if (raw_json == std::string("")){
		LOG("%s: failed reading config from %s\n", __func__, path.c_str());
		return false;
	}

	nlohmann::json parsed_json;
	try{
		parsed_json = nlohmann::json::parse(raw_json);
	}catch(...){
		LOG("%s: failed parsing %s\n", __func__, path.c_str());
		return false;
	}

	#define PARSE_INTEGER(name) { \
		auto itr = parsed_json.find(STR(name)); \
		if (itr == parsed_json.end()){ \
			LOG("%s: %s is missing from config\n", __func__, STR(name)); \
			return false; \
		} \
		if (!itr.value().is_number_integer()){ \
			LOG("%s: %s is not an integer value\n", __func__, STR(name)); \
			return false; \
		} \
		out.name = itr.value(); \
	}
	#define PARSE_STRING(name) { \
		auto itr = parsed_json.find(STR(name)); \
		if (itr == parsed_json.end()){ \
			LOG("%s: %s is missing from config\n", __func__, STR(name)); \
			return false; \
		} \
		if (!itr.value().is_string()){ \
			LOG("%s: %s is not a string value\n", __func__, STR(name)); \
			return false; \
		} \
		out.name = itr.value(); \
	}
	#define PARSE_BOOL(name) { \
		auto itr = parsed_json.find(STR(name)); \
		if (itr == parsed_json.end()){ \
			LOG("%s: %s is missing from config\n", __func__, STR(name)); \
			return false; \
		} \
		if (!itr.value().is_boolean()){ \
			LOG("%s: %s is not a boolean value\n", __func__, STR(name)); \
			return false; \
		} \
		out.name = itr.value(); \
	}

	PARSE_INTEGER(target_tick_interval_ms);
	PARSE_INTEGER(target_tick_interval_idle_ms);
	PARSE_STRING(ip_addr);
	PARSE_INTEGER(port);
	PARSE_INTEGER(num_threads);
	PARSE_INTEGER(session_init_time_limit_ms);
	PARSE_INTEGER(data_queue_size_limit_byte);
	PARSE_INTEGER(connect_time_limit_ms);
	PARSE_INTEGER(max_num_sessions);
	PARSE_BOOL(strict_mode);
	PARSE_INTEGER(max_num_sessions_per_mac);
	PARSE_BOOL(enable_adhocctl);
	PARSE_INTEGER(adhocctl_target_tick_interval_ms);
	PARSE_INTEGER(adhocctl_target_tick_interval_idle_ms);
	PARSE_INTEGER(adhocctl_port);
	PARSE_INTEGER(adhocctl_num_threads);
	PARSE_INTEGER(adhocctl_data_queue_size_limit_byte);
	PARSE_BOOL(adhocctl_relay_only);
	PARSE_INTEGER(adhocctl_timeout_ms);
	PARSE_INTEGER(adhocctl_max_num_sessions);
	PARSE_INTEGER(http_status_server_port);

	#undef PARSE_INTEGER
	#undef PARSE_STRING
	#undef PARSE_BOOL

	return true;
}

void dump_config_to_log(const struct config &config){
	LOG("--- begin config dump ---\n");
	#define DUMP_INTEGER(name) { \
		LOG("%s(integer): %lld\n", STR(name), (int64_t)config.name); \
	}
	#define DUMP_STRING(name) { \
		LOG("%s(string): %s\n", STR(name), config.name.c_str()); \
	}
	#define DUMP_BOOL(name) { \
		LOG("%s(bool): %s\n", STR(name), config.name ? "true" : "false"); \
	}

	DUMP_INTEGER(target_tick_interval_ms);
	DUMP_INTEGER(target_tick_interval_idle_ms);
	DUMP_STRING(ip_addr);
	DUMP_INTEGER(port);
	DUMP_INTEGER(num_threads);
	DUMP_INTEGER(session_init_time_limit_ms);
	DUMP_INTEGER(data_queue_size_limit_byte);
	DUMP_INTEGER(connect_time_limit_ms);
	DUMP_INTEGER(max_num_sessions);
	DUMP_BOOL(strict_mode);
	DUMP_INTEGER(max_num_sessions_per_mac);
	DUMP_BOOL(enable_adhocctl);
	DUMP_INTEGER(adhocctl_target_tick_interval_ms);
	DUMP_INTEGER(adhocctl_target_tick_interval_idle_ms);
	DUMP_INTEGER(adhocctl_port);
	DUMP_INTEGER(adhocctl_num_threads);
	DUMP_INTEGER(adhocctl_data_queue_size_limit_byte);
	DUMP_BOOL(adhocctl_relay_only);
	DUMP_INTEGER(adhocctl_timeout_ms);
	DUMP_INTEGER(adhocctl_max_num_sessions);
	DUMP_INTEGER(http_status_server_port);

	#undef DUMP_INTEGER
	#undef DUMP_STRING
	#undef DUMP_BOOL
}

}
