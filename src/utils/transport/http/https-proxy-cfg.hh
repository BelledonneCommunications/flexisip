/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

namespace flexisip {

/**
 * HTTPS proxy configuration.
 */
class HttpsProxyCfg {
public:
	HttpsProxyCfg(const std::string& host, const int port, const std::string& username, const std::string& password)
	    : mHost(host), mPort(port), mUsername(username), mPassword(password) {}
	~HttpsProxyCfg() = default;

	const std::string& getHost() const {
		return mHost;
	}
	int getPort() const {
		return mPort;
	}
	const std::string& getUsername() const {
		return mUsername;
	}
	const std::string& getPassword() const {
		return mPassword;
	}

private:
	std::string mHost;
	int mPort;
	std::string mUsername;
	std::string mPassword;
};

} /* namespace flexisip */