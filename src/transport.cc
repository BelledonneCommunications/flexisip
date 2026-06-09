/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include <strings.h>

#include "modules/module-toolbox.hh"
#include "transport.hh"

using namespace std;

namespace flexisip {

bool Transport::isSameHost(const string& host) const {
	return module_toolbox::urlHostMatch(host, mHostname) || module_toolbox::urlHostMatch(host, mAddrBinding) ||
	       module_toolbox::urlHostMatch(host, mResolvedIpv4) || module_toolbox::urlHostMatch(host, mResolvedIpv6);
}

bool Transport::is(const string& host, string port) const {
	if (host.empty()) {
		return false;
	}
	if (port.empty()) {
		strcasecmp(mProtocol.c_str(), "tls") == 0 ? port = "5061" : port = "5060";
	}
	if (port == mPort) {
		return isSameHost(host);
	}
	return false;
}

} // namespace flexisip