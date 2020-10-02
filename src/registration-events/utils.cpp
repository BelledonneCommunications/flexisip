/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

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

#include <flexisip/registrardb.hh>

#include "conference/conference-server.hh"

#include "utils.hh"

namespace flexisip {

namespace RegistrationEvent {

int Utils::getMaskFromSpecs (const string &specs) {
    unsigned int mask = 0;

    //Please excuse the following code that is a bit too basic in terms of parsing:
    if (specs.find("groupchat") != string::npos) mask |= (unsigned int)ChatRoomCapabilities::Conference;
    if (specs.find("lime") != string::npos) mask |= (unsigned int)ChatRoomCapabilities::Encrypted;
    return mask;
}

bool Utils::isContactCompatible(const ConferenceServer & server, const shared_ptr<ChatRoom> &cr, const string &specs) {
	int mask = Utils::getMaskFromSpecs(specs);
	unsigned int chatRoomCapabilities = cr->getCapabilities() & ~(int)ChatRoomCapabilities::OneToOne;
	return (!server.capabilityCheckEnabled() || (mask & chatRoomCapabilities) == chatRoomCapabilities);
}

string Utils::getDeviceName(const shared_ptr<ExtendedContact> &ec) {
	const string &userAgent = ec->getUserAgent();
	size_t begin = userAgent.find("(");
	string deviceName;
	if (begin != string::npos) {
		size_t end = userAgent.find(")", begin);
		size_t openingParenthesis = userAgent.find("(", begin + 1);
		while (openingParenthesis != string::npos && openingParenthesis < end) {
			openingParenthesis = userAgent.find("(", openingParenthesis + 1);
			end = userAgent.find(")", end + 1);
		}
		if (end != string::npos){
			deviceName = userAgent.substr(begin + 1, end - (begin + 1));
		}
	}
	return deviceName;
}

}

}
