// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stdio.h>

#include <map>
#include <string>
#include <set>

#include "log.h"

namespace aemu_postoffice_adhocctl_server {

struct game_db {
	std::map<std::string, std::string> crosslinks; // game id keyed
	std::map<std::string, std::string> names; // game id keyed
	std::set<std::string> cod_quirk_games; // game ids of games that uses truncated game id as group name
};

bool parse_game_db_from_json(std::string path, struct game_db &out);
bool game_db_same(const struct game_db &left, const struct game_db &right);

}

