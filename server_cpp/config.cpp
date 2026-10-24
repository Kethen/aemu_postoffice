// SPDX-License-Identifier: GPL-3.0-only
#include "config.h"
#include "file_util.h"
#include "log.h"
#include "native_socket.h"

#include "../ext/json/json.hpp"

#define STR(s) #s

namespace aemu_postoffice_server {

bool parse_config_from_json(std::string path, struct config &out, std::unordered_set<std::string> &defaulted_keys, std::unordered_set<std::string> &forced_keys){
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

	struct config default_config = {};
	bool good_config = true;
	defaulted_keys.clear();
	forced_keys.clear();

	#define PARSE_INTEGER(name) { \
		auto itr = parsed_json.find(STR(name)); \
		if (itr == parsed_json.end()){ \
			LOG("%s: %s is missing from config, using default %lld\n", __func__, STR(name), (int64_t)default_config.name); \
			good_config = false; \
			out.name = default_config.name; \
			defaulted_keys.insert(std::string(STR(name))); \
		} else if (!itr.value().is_number_integer()){ \
			LOG("%s: %s is not an integer value, using default %lld\n", __func__, STR(name), (int64_t)default_config.name); \
			good_config = false; \
			out.name = default_config.name; \
			defaulted_keys.insert(std::string(STR(name))); \
		} else { \
			out.name = itr.value(); \
		} \
	}
	#define PARSE_STRING(name) { \
		auto itr = parsed_json.find(STR(name)); \
		if (itr == parsed_json.end()){ \
			LOG("%s: %s is missing from config, using default %s\n", __func__, STR(name), default_config.name.c_str()); \
			good_config = false; \
			out.name = default_config.name; \
			defaulted_keys.insert(std::string(STR(name))); \
		} else if (!itr.value().is_string()){ \
			LOG("%s: %s is not a string value, using default %s\n", __func__, STR(name), default_config.name.c_str()); \
			good_config = false; \
			out.name = default_config.name; \
			defaulted_keys.insert(std::string(STR(name))); \
		} else { \
			out.name = itr.value(); \
		} \
	}
	#define PARSE_BOOL(name) { \
		auto itr = parsed_json.find(STR(name)); \
		if (itr == parsed_json.end()){ \
			LOG("%s: %s is missing from config, using default %s\n", __func__, STR(name), default_config.name ? "true" : "false"); \
			good_config = false; \
			out.name = default_config.name; \
			defaulted_keys.insert(std::string(STR(name))); \
		} else if (!itr.value().is_boolean()){ \
			LOG("%s: %s is not a boolean value, using default %s\n", __func__, STR(name), default_config.name ? "true" : "false"); \
			good_config = false; \
			out.name = default_config.name; \
			defaulted_keys.insert(std::string(STR(name))); \
		} else { \
			out.name = itr.value(); \
		} \
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
	PARSE_INTEGER(adhocctl_max_num_sessions_per_ip);
	PARSE_INTEGER(http_status_server_port);

	#undef PARSE_INTEGER
	#undef PARSE_STRING
	#undef PARSE_BOOL

	// validation and sanitization

	#define CHECK_INTEGER(name, check) { \
		if (out.name check){ \
			LOG("%s: bad %s %lld, using default %lld instead\n", __func__, STR(name), (int64_t)out.name, (int64_t)default_config.name); \
			out.name = default_config.name; \
			good_config = false; \
			defaulted_keys.insert(std::string(STR(name))); \
		} \
	}
	CHECK_INTEGER(target_tick_interval_ms, <= 0);
	CHECK_INTEGER(target_tick_interval_idle_ms, <= 0);

	AddrFamily addr_family = get_addr_family(out.ip_addr);
	if (addr_family == AddrFamily::UNKNOWN) {
		LOG("%s: bad ip_addr %s, using default %s instead\n", __func__, out.ip_addr.c_str(), default_config.ip_addr.c_str());
		out.ip_addr = default_config.ip_addr;
		good_config = false;
		defaulted_keys.insert(std::string("ip_addr"));
	}

	CHECK_INTEGER(port, <= 0);
	CHECK_INTEGER(port, > 65535);
	CHECK_INTEGER(num_threads, <= 0);
	CHECK_INTEGER(session_init_time_limit_ms, < 500);
	CHECK_INTEGER(data_queue_size_limit_byte, < 1024);
	CHECK_INTEGER(connect_time_limit_ms, < 1000);
	CHECK_INTEGER(max_num_sessions, < 2);
	CHECK_INTEGER(max_num_sessions_per_mac, < 1);
	CHECK_INTEGER(adhocctl_target_tick_interval_ms, <= 0);
	CHECK_INTEGER(adhocctl_target_tick_interval_idle_ms, <= 0);
	CHECK_INTEGER(adhocctl_port, <= 0);
	CHECK_INTEGER(adhocctl_port, > 65535);
	CHECK_INTEGER(adhocctl_num_threads, <= 0);
	CHECK_INTEGER(adhocctl_data_queue_size_limit_byte, < 512);
	CHECK_INTEGER(adhocctl_timeout_ms, < 30000);
	CHECK_INTEGER(adhocctl_max_num_sessions, < 2);
	CHECK_INTEGER(adhocctl_max_num_sessions_per_ip, < 1);
	CHECK_INTEGER(http_status_server_port, <= 0);
	CHECK_INTEGER(http_status_server_port, > 65535);

	if (addr_family == AddrFamily::IPV6 && !out.adhocctl_relay_only) {
		LOG("%s: ipv6 dual stack mode is used, adhocctl_relay_only must also be true\n", __func__);
		out.adhocctl_relay_only = true;
		good_config = false;
		forced_keys.insert("adhocctl_relay_only");
	}

	if (!out.enable_adhocctl && out.strict_mode) {
		LOG("%s: enable_adhocctl is set to false, strict_mode must also be false\n", __func__);
		out.strict_mode = false;
		good_config = false;
		forced_keys.insert("strict_mode");
	}

	#undef CHECK_INTEGER

	return good_config;
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
	DUMP_INTEGER(adhocctl_max_num_sessions_per_ip);
	DUMP_INTEGER(http_status_server_port);

	#undef DUMP_INTEGER
	#undef DUMP_STRING
	#undef DUMP_BOOL
}

bool merge_config(struct config &merge_into, const struct config &merge_from){
	bool config_changed = false;
	#define COPY(name) { \
		if (merge_into.name != merge_from.name) { \
			config_changed = true; \
			merge_into.name = merge_from.name ; \
		} \
	}
	#define NO_RUNTIME_CHANGE(name) { \
		if (merge_into.name != merge_from.name) { \
			LOG("%s: %s cannot be changed runtime, please relaunch\n", __func__, STR(name)); \
		} \
	}
	#define COPY_WARN(name) { \
		if (merge_into.name != merge_from.name) { \
			LOG("%s: relaunch is recommended when changing %s\n", __func__, STR(name)); \
			COPY(name); \
		} \
	}
	COPY(target_tick_interval_ms);
	COPY(target_tick_interval_idle_ms);
	NO_RUNTIME_CHANGE(ip_addr);
	NO_RUNTIME_CHANGE(port);
	NO_RUNTIME_CHANGE(num_threads);
	COPY(session_init_time_limit_ms);
	COPY(data_queue_size_limit_byte);
	COPY(connect_time_limit_ms);
	COPY_WARN(max_num_sessions);
	NO_RUNTIME_CHANGE(strict_mode);
	COPY(max_num_sessions_per_mac);
	NO_RUNTIME_CHANGE(enable_adhocctl);
	COPY(adhocctl_target_tick_interval_ms);
	COPY(adhocctl_target_tick_interval_idle_ms);
	NO_RUNTIME_CHANGE(adhocctl_port);
	NO_RUNTIME_CHANGE(adhocctl_num_threads);
	COPY(adhocctl_data_queue_size_limit_byte);
	NO_RUNTIME_CHANGE(adhocctl_relay_only);
	COPY(adhocctl_timeout_ms);
	COPY_WARN(adhocctl_max_num_sessions);
	COPY(adhocctl_max_num_sessions_per_ip);
	NO_RUNTIME_CHANGE(http_status_server_port);

	return config_changed;
}

}
