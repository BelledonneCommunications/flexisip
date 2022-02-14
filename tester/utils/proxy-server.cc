/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "proxy-server.hh"
#include "flexisip/registrardb.hh"

using namespace flexisip;
using namespace std;
using namespace std::chrono;
/**
 * A class to manage the flexisip proxy server
 */
Server::Server(const std::string& configFile) {
	// Agent initialisation
	mRoot = make_shared<sofiasip::SuRoot>();
	mAgent = make_shared<Agent>(mRoot);

	if (!configFile.empty()) {
		GenericManager* cfg = GenericManager::get();

		auto configFilePath = bcTesterRes(configFile);
		int ret = -1;
		if (bctbx_file_exist(configFilePath.c_str()) == 0) {
			ret = cfg->load(configFilePath);
		} else {
			ret = cfg->load(string(TESTER_DATA_DIR).append(configFile));
		}
		if (ret != 0) {
			BC_FAIL("Unable to load configuration file");
		}
		mAgent->loadConfig(cfg);
	}
}

Server::~Server() {
	mAgent->unloadConfig();
	RegistrarDb::resetDB();
}

void Server::runFor(std::chrono::milliseconds duration) {
	auto beforePlusDuration = steady_clock::now() + duration;
	while (beforePlusDuration >= steady_clock::now()) {
		mRoot->step(100ms);
	}
}
