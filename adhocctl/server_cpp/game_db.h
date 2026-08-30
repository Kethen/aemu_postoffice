#pragma once

#include <stdio.h>

#include <unordered_map>
#include <string>

#include "log.h"

namespace aemu_postoffice_adhocctl_server {

struct game_db {
	std::unordered_map<std::string, std::string> crosslinks; // game id keyed
	std::unordered_map<std::string, std::string> names; // game id keyed
};

bool parse_game_db_from_json(std::string path, struct game_db &out);

}

