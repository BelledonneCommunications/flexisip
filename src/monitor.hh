/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <string>

#include "agent.hh"
#include "auth/db/authdb.hh"

namespace flexisip {

class Monitor {
public:
	static void exec(ConfigManager& cfg, int socket);
	static void createAccounts(std::shared_ptr<AuthDbBackendOwner> authDbOwner, GenericStruct& rootConfig);

private:
	static std::string findLocalAddress(const std::list<std::string>& nodes);
	static bool isLocalhost(const std::string& host);
	static bool notLocalhost(const std::string& host);
	static std::string md5sum(const std::string& s);
	static std::string generateUsername(const std::string& prefix, const std::string& host);
	static std::string generatePassword(const std::string& host, const std::string& salt);
	static std::string findDomain(GenericStruct& rootConfig);

	static const std::string SCRIPT_PATH;
	static const std::string CALLER_PREFIX;
	static const std::string CALLEE_PREFIX;
	static const int PASSWORD_CACHE_EXPIRE;
};

} // namespace flexisip
