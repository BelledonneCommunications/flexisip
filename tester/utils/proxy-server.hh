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

#pragma once
#include "../tester.hh"
/**
 * A class to manage the flexisip proxy server
 */
class Server {
private:
	std::shared_ptr<sofiasip::SuRoot> mRoot;
	std::shared_ptr<flexisip::Agent> mAgent;

public:
	// Accessors
	std::shared_ptr<sofiasip::SuRoot> getRoot() noexcept {
		return mRoot;
	}

	std::shared_ptr<flexisip::Agent> getAgent() noexcept {
		return mAgent;
	}

	void start() {
		mAgent->start("", "");
	}

	/**
	 * Create the sofiasip root, the Agent and load the config file given as parameter
	 *
	 * @param[in] configFile	The path to config file. Search for it in the resource directory and TESTER_DATA_DIR
	 */
	Server(const std::string& configFile = std::string());
	~Server();
}; // Class Server
