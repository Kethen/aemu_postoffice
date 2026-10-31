// SPDX-License-Identifier: GPL-3.0-only
#include "game_db.h"
#include "../../ext/json/json.hpp"

#include <stdio.h>
#include <stdlib.h>

bool write_file(const std::string &path, const std::string &data){
	FILE *out_file = fopen(path.c_str(), "w");

	if (out_file == NULL){
		printf("%s: failed opening %s for writing\n", __func__, path.c_str());
		exit(1);
		return false;
	}

	int write_result = fwrite(data.data(), data.size(), 1, out_file);

	fclose(out_file);
	if (write_result != 1){
		printf("%s: failed writing to %s\n", __func__, path.c_str());
		exit(1);
		return false;
	}

	return true;
}

using namespace aemu_postoffice_adhocctl_server;

static const std::string test_path = std::string("./test_game_db.json");

void test_parsing(){
	// missing object test
	nlohmann::json test_game_db;
	test_game_db["names"] = nlohmann::json::object();
	test_game_db["cod_quirk_games"] = nlohmann::json::array();
	write_file(test_path, test_game_db.dump());

	struct game_db parse_output;

	bool parse_result = parse_game_db_from_json(test_path, parse_output);
	if (parse_result == true){
		printf("%s: parsing somehow returned true with a game db missing crosslinks\n", __func__);
		exit(1);
	}

	test_game_db = nlohmann::json::object();
	test_game_db["crosslinks"] = nlohmann::json::object();
	test_game_db["cod_quirk_games"] = nlohmann::json::array();
	write_file(test_path, test_game_db.dump());

	parse_result = parse_game_db_from_json(test_path, parse_output);
	if (parse_result == true){
		printf("%s: parsing somehow returned true with a game db missing names\n", __func__);
		exit(1);
	}

	test_game_db = nlohmann::json::object();
	test_game_db["crosslinks"] = nlohmann::json::object();
	test_game_db["names"] = nlohmann::json::object();
	write_file(test_path, test_game_db.dump());

	parse_result = parse_game_db_from_json(test_path, parse_output);
	if (parse_result == true){
		printf("%s: parsing somehow returned true with a game db missing cod_quirk_games\n", __func__);
		exit(1);
	}

	std::map<std::string, std::string> crosslink_expectation;
	crosslink_expectation["efgh12345"] = "abcd12345";
	crosslink_expectation["defg12345"] = "abcd12345";
	std::map<std::string, std::string> name_expectation;
	name_expectation["abcd12345"] = "an awesome game";
	name_expectation["bcde12345"] = "another awesome game";
	std::set<std::string> cod_quirk_games_expectation;
	cod_quirk_games_expectation.insert("aabb11223");
	cod_quirk_games_expectation.insert("bbcc22334");

	test_game_db = nlohmann::json::object();
	test_game_db["crosslinks"] = nlohmann::json::object();
	for (auto expectation = crosslink_expectation.begin();expectation != crosslink_expectation.end();expectation++){
		test_game_db["crosslinks"][expectation->first] = expectation->second;
	}
	for (auto expectation = name_expectation.begin();expectation != name_expectation.end();expectation++){
		test_game_db["names"][expectation->first] = expectation->second;
	}
	for(auto expectation = cod_quirk_games_expectation.begin();expectation != cod_quirk_games_expectation.end();expectation++){
		test_game_db["cod_quirk_games"].push_back(*expectation);
	}
	write_file(test_path, test_game_db.dump());

	parse_result = parse_game_db_from_json(test_path, parse_output);
	if (parse_result == false){
		printf("%s: valid game db parsing failed somehow\n", __func__);
		exit(1);
	}

	if (parse_output.crosslinks.size() != 2){
		printf("%s: parse output has bad crosslink map size\n", __func__);
		exit(1);
	}

	if (parse_output.names.size() != 2){
		printf("%s: parse output has bad name map size\n", __func__);
		exit(1);
	}

	if (parse_output.cod_quirk_games.size() != 2){
		printf("%s: parse output has bad cod_quirk_games size\n", __func__);
		exit(1);
	}

	for (auto expectation = crosslink_expectation.begin();expectation != crosslink_expectation.end();expectation++){
		auto parsed_result_itr = parse_output.crosslinks.find(expectation->first);
		if (parsed_result_itr == parse_output.crosslinks.end()){
			printf("%s: crosslink %s -> %s is missing from parse result\n", __func__, expectation->first.c_str(), expectation->second.c_str());
			exit(1);
		}
		if (parsed_result_itr->second != expectation->second){
			printf("%s: crosslink %s -> %s is wrong\n", __func__, expectation->first.c_str(), expectation->second.c_str());
			exit(1);
		}
	}

	for (auto expectation = name_expectation.begin();expectation != name_expectation.end();expectation++){
		auto parsed_result_itr = parse_output.names.find(expectation->first);
		if (parsed_result_itr == parse_output.names.end()){
			printf("%s: name %s -> %s is missing from parse result\n", __func__, expectation->first.c_str(), expectation->second.c_str());
			exit(1);
		}
		if (parsed_result_itr->second != expectation->second){
			printf("%s: name %s -> %s is wrong\n", __func__, expectation->first.c_str(), expectation->second.c_str());
			exit(1);
		}
	}
	for(auto expectation = cod_quirk_games_expectation.begin();expectation != cod_quirk_games_expectation.end();expectation++){
		if (parse_output.cod_quirk_games.find(*expectation) == parse_output.cod_quirk_games.end()){
			printf("%s: cod quirk game %s is missing\n", __func__, expectation->c_str());
			exit(1);
		}
	}
}

void test_compare(){
	struct game_db left;
	left.crosslinks["efgh12345"] = "abcd12345";
	left.crosslinks["defg12345"] = "abcd12345";
	left.names["abcd12345"] = "an awesome game";
	left.names["bcde12345"] = "another awesome game";
	left.cod_quirk_games.insert("aabb11223");
	left.cod_quirk_games.insert("bbcc22334");

	struct game_db right = left;
	if (!game_db_same(left, right)){
		printf("%s: same db is somehow different\n", __func__);
		exit(1);
	}

	// entry count test
	right.crosslinks.erase(right.crosslinks.begin());
	if (game_db_same(left, right)){
		printf("%s: -1 crosslink entry is somehow same\n", __func__);
		exit(1);
	}

	right = left;
	right.names.erase(right.names.begin());
	if (game_db_same(left, right)){
		printf("%s: -1 name entry is somehow same\n", __func__);
		exit(1);
	}

	right = left;
	right.cod_quirk_games.erase(right.cod_quirk_games.begin());
	if (game_db_same(left, right)){
		printf("%s: -1 cod quirk game entry is somehow same\n", __func__);
		exit(1);
	}

	// entry content test
	right = left;
	right.crosslinks.erase(right.crosslinks.begin());
	right.crosslinks["cdef12345"] = "abcd12345";
	if (game_db_same(left, right)){
		printf("%s: different crosslink key entry is somehow same\n", __func__);
		exit(1);
	}

	right = left;
	right.crosslinks["defg12345"] = "abcd54321";
	if (game_db_same(left, right)){
		printf("%s: different crosslink value entry is somehow same\n", __func__);
		exit(1);
	}

	right = left;
	right.names.erase(right.names.begin());
	right.names["abcd54321"] = "another awesome game";
	if (game_db_same(left, right)){
		printf("%s: different name key entry is somehow same\n", __func__);
		exit(1);
	}

	right = left;
	right.names["bcde12345"] = "yet another awesome game";
	if (game_db_same(left, right)){
		printf("%s: different name value entry is somehow same\n", __func__);
		exit(1);
	}

	right = left;
	right.cod_quirk_games.erase(right.cod_quirk_games.begin());
	right.cod_quirk_games.insert("uucc5587");
	if (game_db_same(left, right)){
		printf("%s: different cod quirk games set is somehow the same\n", __func__);
		exit(1);
	}
}

int main(){
	test_parsing();
	test_compare();

	printf("%s: test ok\n", __func__);

	return 0;
}
