/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

class Transport {
public:
	Transport() = default;
	Transport(const std::string& hostname, const std::string& port, const std::string& protocol,
	          const std::string& resolvedIpv4, const std::string& resolvedIpv6, const std::string& addrBiding)
	    : mHostname{hostname}, mPort{port}, mProtocol{protocol}, mResolvedIpv4{resolvedIpv4},
	      mResolvedIpv6{resolvedIpv6}, mAddrBiding{addrBiding} {};
	~Transport() = default;

	bool is(const std::string& host, std::string port) const;

	const std::string& getAddrBiding() const {
		return mAddrBiding;
	}

	const std::string& getHostname() const {
		return mHostname;
	}

	const std::string& getPort() const {
		return mPort;
	}

	const std::string& getProtocol() const {
		return mProtocol;
	}

	const std::string& getResolvedIpv4() const {
		return mResolvedIpv4;
	}

	const std::string& getResolvedIpv6() const {
		return mResolvedIpv6;
	}
private:
	std::string mHostname{};
	std::string mPort{};
	std::string mProtocol{};
	std::string mResolvedIpv4{};
	std::string mResolvedIpv6{};
	std::string mAddrBiding{};
};

} // namespace flexisip
