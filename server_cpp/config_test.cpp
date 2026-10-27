#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "../ext/json/json.hpp"
#include "file_util.h"

#define STR(s) #s

bool write_to_file(const std::string &content, std::string path){
	FILE *out_file = fopen(path.c_str(), "w");
	if (out_file == NULL){
		printf("%s: failed opening %s for writing\n", __func__, path.c_str());
		exit(1);
		return false;
	}

	int write_status = fwrite(content.data(), content.size(), 1, out_file);
	fclose(out_file);
	if (write_status != 1){
		printf("%s: failed writing to %s\n", __func__, path.c_str());
		exit(1);
		return false;
	}

	return true;
}

using namespace aemu_postoffice_server;

int main(){
	std::string test_config_path("./test_config.json");
	struct config default_config = {};
	nlohmann::json test_config = {};

	write_to_file(std::string("{}"), test_config_path);

	struct config parsed_config;
	std::unordered_set<std::string> defaulted_keys;
	std::unordered_set<std::string> forced_keys;
	bool parse_result = parse_config_from_json(test_config_path, parsed_config, defaulted_keys, forced_keys);
	if (parse_result != false){
		printf("%s: bad config parsed as good config\n", __func__);
		exit(1);
	}
	#define SHOULD_BE_DEFAULTED(name) { \
		if (defaulted_keys.find(std::string(STR(name))) == defaulted_keys.end()){ \
			printf("%s: %s should have been defaulted\n", __func__, STR(name));\
			exit(1); \
		} \
	}
	#define SHOULD_BE_FORCED(name) { \
		if (forced_keys.find(std::string(STR(name))) == forced_keys.end()){ \
			printf("%s: %s should have been forced\n", __func__, STR(name));\
			exit(1); \
		} \
	}
	SHOULD_BE_DEFAULTED(target_tick_interval_ms);
	SHOULD_BE_DEFAULTED(target_tick_interval_idle_ms);
	SHOULD_BE_DEFAULTED(ip_addr);
	SHOULD_BE_DEFAULTED(port);
	SHOULD_BE_DEFAULTED(num_threads);
	SHOULD_BE_DEFAULTED(session_init_time_limit_ms);
	SHOULD_BE_DEFAULTED(data_queue_size_limit_byte);
	SHOULD_BE_DEFAULTED(connect_time_limit_ms);
	SHOULD_BE_DEFAULTED(max_num_sessions);
	SHOULD_BE_DEFAULTED(strict_mode);
	SHOULD_BE_DEFAULTED(max_num_sessions_per_mac);
	SHOULD_BE_DEFAULTED(enable_adhocctl);
	SHOULD_BE_DEFAULTED(adhocctl_target_tick_interval_ms);
	SHOULD_BE_DEFAULTED(adhocctl_target_tick_interval_idle_ms);
	SHOULD_BE_DEFAULTED(adhocctl_port);
	SHOULD_BE_DEFAULTED(adhocctl_num_threads);
	SHOULD_BE_DEFAULTED(adhocctl_data_queue_size_limit_byte);
	SHOULD_BE_DEFAULTED(adhocctl_relay_only);
	SHOULD_BE_DEFAULTED(adhocctl_timeout_ms);
	SHOULD_BE_DEFAULTED(adhocctl_max_num_sessions);
	SHOULD_BE_DEFAULTED(adhocctl_max_num_sessions_per_ip);
	SHOULD_BE_DEFAULTED(http_status_server_port);

	#define ASSIGN_DEFAULT(name) { \
	test_config[STR(name)] = default_config.name; \
	}
	ASSIGN_DEFAULT(target_tick_interval_ms);
	ASSIGN_DEFAULT(target_tick_interval_idle_ms);
	ASSIGN_DEFAULT(ip_addr);
	ASSIGN_DEFAULT(port);
	ASSIGN_DEFAULT(num_threads);
	ASSIGN_DEFAULT(session_init_time_limit_ms);
	ASSIGN_DEFAULT(data_queue_size_limit_byte);
	ASSIGN_DEFAULT(connect_time_limit_ms);
	ASSIGN_DEFAULT(max_num_sessions);
	ASSIGN_DEFAULT(strict_mode);
	ASSIGN_DEFAULT(max_num_sessions_per_mac);
	ASSIGN_DEFAULT(enable_adhocctl);
	ASSIGN_DEFAULT(adhocctl_target_tick_interval_ms);
	ASSIGN_DEFAULT(adhocctl_target_tick_interval_idle_ms);
	ASSIGN_DEFAULT(adhocctl_port);
	ASSIGN_DEFAULT(adhocctl_num_threads);
	ASSIGN_DEFAULT(adhocctl_data_queue_size_limit_byte);
	ASSIGN_DEFAULT(adhocctl_relay_only);
	ASSIGN_DEFAULT(adhocctl_timeout_ms);
	ASSIGN_DEFAULT(adhocctl_max_num_sessions);
	ASSIGN_DEFAULT(adhocctl_max_num_sessions_per_ip);
	ASSIGN_DEFAULT(http_status_server_port);

	write_to_file(test_config.dump(), test_config_path);

	parse_result = parse_config_from_json(test_config_path, parsed_config, defaulted_keys, forced_keys);
	if (parse_result == false) {
		printf("%s: default config parsed as bad config\n", __func__);
		exit(1);
	}
	if (defaulted_keys.size() != 0) {
		for (auto &key : defaulted_keys){
			printf("%s: unexpected defaulted key %s\n", __func__, key.c_str());
		}
		exit(1);
	}
	if (forced_keys.size() != 0) {
		for (auto &key : forced_keys){
			printf("%s: unexpected forced key %s\n", __func__, key.c_str());
		}
		exit(1);
	}
	#define CHECK_DEFAULT(name) { \
		if (parsed_config.name != default_config.name) { \
			printf("%s: %s is expected to be default\n", __func__, STR(name)); \
			exit(1); \
		} \
	}
	CHECK_DEFAULT(target_tick_interval_ms);
	CHECK_DEFAULT(target_tick_interval_idle_ms);
	CHECK_DEFAULT(ip_addr);
	CHECK_DEFAULT(port);
	CHECK_DEFAULT(num_threads);
	CHECK_DEFAULT(session_init_time_limit_ms);
	CHECK_DEFAULT(data_queue_size_limit_byte);
	CHECK_DEFAULT(connect_time_limit_ms);
	CHECK_DEFAULT(max_num_sessions);
	CHECK_DEFAULT(strict_mode);
	CHECK_DEFAULT(max_num_sessions_per_mac);
	CHECK_DEFAULT(enable_adhocctl);
	CHECK_DEFAULT(adhocctl_target_tick_interval_ms);
	CHECK_DEFAULT(adhocctl_target_tick_interval_idle_ms);
	CHECK_DEFAULT(adhocctl_port);
	CHECK_DEFAULT(adhocctl_num_threads);
	CHECK_DEFAULT(adhocctl_data_queue_size_limit_byte);
	CHECK_DEFAULT(adhocctl_relay_only);
	CHECK_DEFAULT(adhocctl_timeout_ms);
	CHECK_DEFAULT(adhocctl_max_num_sessions);
	CHECK_DEFAULT(adhocctl_max_num_sessions_per_ip);
	CHECK_DEFAULT(http_status_server_port);

	test_config["enable_adhocctl"] = false;
	write_to_file(test_config.dump(), test_config_path);
	parse_result = parse_config_from_json(test_config_path, parsed_config, defaulted_keys, forced_keys);
	if (parse_result != false){
		printf("%s: parse was expected to fail due to adhocctl disabled + strict mode\n", __func__);
		exit(1);
	}
	if (forced_keys.size() != 1 || forced_keys.find("strict_mode") == forced_keys.end() || parsed_config.strict_mode){
		printf("%s: strict_mode should have been force disabed\n", __func__);
		exit(1);
	}

	test_config["enable_adhocctl"] = true;
	test_config["adhocctl_relay_only"] = false;
	write_to_file(test_config.dump(), test_config_path);
	parse_result = parse_config_from_json(test_config_path, parsed_config, defaulted_keys, forced_keys);
	if (parse_result != false){
		printf("%s: parse was expected to fail adhocctl relay only mode disabled with ipv6 address\n", __func__);
		exit(1);
	}
	if (forced_keys.size() != 1 || forced_keys.find("adhocctl_relay_only") == forced_keys.end() || !parsed_config.adhocctl_relay_only){
		printf("%s: adhocctl_relay_only should have been force enabled\n", __func__);
		exit(1);
	}

	printf("%s: test ok\n", __func__);

	return 0;
}
