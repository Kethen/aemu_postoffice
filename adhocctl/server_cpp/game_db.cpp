// SPDX-License-Identifier: GPL-3.0-only
#include "game_db.h"
#include "log.h"
#include "../../server_cpp/file_util.h"
#include "../../ext/json/json.hpp"

namespace aemu_postoffice_adhocctl_server {

bool parse_game_db_from_json(std::string path, struct game_db &out){
	out.crosslinks.clear();
	out.names.clear();
	out.cod_quirk_games.clear();

	std::string raw_json = aemu_postoffice_server::read_file_to_string(path);
	if (raw_json == std::string("")){
		LOG("%s: failed reading json file %s\n", __func__, path.c_str());
		return false;
	}

	nlohmann::json parsed_json;
	try{
		parsed_json = nlohmann::json::parse(raw_json);
	}catch(...){
		LOG("%s: exception occured while parsing %s\n", __func__, path.c_str());
		return false;
	}

	auto crosslinks = parsed_json.find("crosslinks");
	if (crosslinks == parsed_json.end()){
		LOG("%s: crosslinks not found in json\n", __func__);
		return false;
	}
	if (!crosslinks.value().is_object()){
		LOG("%s: crosslinks is not an object\n", __func__);
		return false;
	}

	auto names = parsed_json.find("names");
	if (names == parsed_json.end()){
		LOG("%s: names not found in json\n", __func__);
		return false;
	}
	if (!names.value().is_object()){
		LOG("%s: names is not an object\n", __func__);
		return false;
	}

	auto cod_quirk_games = parsed_json.find("cod_quirk_games");
	if (cod_quirk_games == parsed_json.end()){
		LOG("%s: cod_quirk_games not found in json\n", __func__);
		return false;
	}
	if (!cod_quirk_games.value().is_array()){
		LOG("%s: cod_quirk_games is not an array\n", __func__);
		return false;
	}

	for (auto entry = crosslinks.value().begin();entry != crosslinks.value().end();entry++){
		if (!entry.value().is_string()){
			LOG("%s: bad non string value on crosslink entry %s\n", __func__, entry.key().c_str());
			out.crosslinks.clear();
			return false;
		}
		out.crosslinks.insert_or_assign(entry.key(), entry.value());
	}

	for (auto entry = names.value().begin();entry != names.value().end();entry++){
		if (!entry.value().is_string()){
			LOG("%s: bad non string value on name entry %s\n", __func__, entry.key().c_str());
			out.names.clear();
			return false;
		}
		out.names.insert_or_assign(entry.key(), entry.value());
	}

	for (auto entry = out.crosslinks.begin();entry != out.crosslinks.end();entry++){
		if (out.crosslinks.find(entry->second) != out.crosslinks.end()){
			LOG("%s: crosslink for entry %s -> %s links an existing crosslink entry, recursive crosslinking is not supported\n", __func__, entry->first.c_str(), entry->second.c_str());
			out.crosslinks.clear();
			return false;
		}
	}

	for (auto entry : cod_quirk_games.value()){
		out.cod_quirk_games.insert(entry);
	}

	return true;
}

bool game_db_same(const struct game_db &left, const struct game_db &right){
	if (left.crosslinks.size() != right.crosslinks.size()){
		return false;
	}
	if (left.names.size() != right.names.size()){
		return false;
	}
	if (left.cod_quirk_games.size() != right.cod_quirk_games.size()){
		return false;
	}

	auto left_crosslink_itr = left.crosslinks.begin();
	auto right_crosslink_itr = right.crosslinks.begin();
	while (true){
		if (left_crosslink_itr == left.crosslinks.end()){
			break;
		}
		if (left_crosslink_itr->first != right_crosslink_itr->first){
			return false;
		}
		if (left_crosslink_itr->second != right_crosslink_itr->second){
			return false;
		}
		left_crosslink_itr++;
		right_crosslink_itr++;
	}

	auto left_name_itr = left.names.begin();
	auto right_name_itr = right.names.begin();
	while (true){
		if (left_name_itr == left.names.end()){
			break;
		}
		if (left_name_itr->first != right_name_itr->first){
			return false;
		}
		if (left_name_itr->second != right_name_itr->second){
			return false;
		}
		left_name_itr++;
		right_name_itr++;
	}

	auto left_cod_quirk_games_itr = left.cod_quirk_games.begin();
	auto right_cod_quirk_games_itr = right.cod_quirk_games.begin();
	while (true){
		if (left_cod_quirk_games_itr == left.cod_quirk_games.end()){
			break;
		}
		if (*left_cod_quirk_games_itr != *right_cod_quirk_games_itr){
			return false;
		}
		left_cod_quirk_games_itr++;
		right_cod_quirk_games_itr++;
	}

	return true;
}

}

