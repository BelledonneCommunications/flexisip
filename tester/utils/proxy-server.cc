/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <algorithm>

#include "bctoolbox/tester.h"

#include <flexisip/registrar/registrar-db.hh>

#include "proxy-server.hh"
#include "tester.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {
namespace tester {

/**
 * A class to manage the flexisip proxy server
 */
Server::Server(const std::string& configFile) {
	if (!configFile.empty()) {
		GenericManager* cfg = GenericManager::get();

		auto configFilePath = bcTesterRes(configFile);
		int ret = -1;
		if (bctbx_file_exist(configFilePath.c_str()) == 0) {
			ret = cfg->load(configFilePath);
		} else {
			ret = cfg->load(bcTesterRes(configFile));
		}
		if (ret != 0) {
			BC_FAIL("Unable to load configuration file");
		}
		mAgent->loadConfig(cfg); // Don't modify cfg before this line as it gets reloaded here

		// For testing purposes, override the auth file path to be relative to the config file.
		const auto& configFolderPath = configFilePath.substr(0, configFilePath.find_last_of('/') + 1);
		auto authFilePath = cfg->getRoot()
		                        ->get<flexisip::GenericStruct>("module::Authentication")
		                        ->get<flexisip::ConfigString>("file-path");
		authFilePath->set(configFolderPath + authFilePath->read());
	}
}

Server::Server(const std::map<std::string, std::string>& config) {
	auto cfg = GenericManager::get();
	cfg->load("");
	for (const auto& kv : config) {
		const auto& key = kv.first;
		const auto& value = kv.second;
		auto slashPos = key.find('/');
		if (slashPos == decay_t<decltype(key)>::npos) {
			throw invalid_argument{"missing '/' in parameter name [" + key + "]"};
		}
		if (slashPos == key.size() - 1) {
			throw invalid_argument{"invalid parameter name [" + key + "]: forbidden ending '/'"};
		}
		auto sectionName = key.substr(0, slashPos);
		auto parameterName = key.substr(slashPos + 1);
		cfg->getRoot()->get<GenericStruct>(sectionName)->get<ConfigValue>(parameterName)->set(value);
	}
	mAgent->loadConfig(cfg, false);
}

Server::~Server() {
	mAgent->unloadConfig();
	RegistrarDb::resetDB();
}

void Server::runFor(std::chrono::milliseconds duration) {
	auto beforePlusDuration = steady_clock::now() + duration;
	while (beforePlusDuration >= steady_clock::now()) {
		mAgent->getRoot()->step(100ms);
	}
}

} // namespace tester
} // namespace flexisip
