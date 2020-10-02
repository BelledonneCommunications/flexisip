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

#pragma once

#include <linphone++/linphone.hh>

#include <flexisip/registrardb.hh>

#include "conference/conference-server.hh"

using namespace std;
using namespace linphone;

namespace flexisip {

namespace RegistrationEvent {
    class Utils {
    public:
        static int getMaskFromSpecs(const string &mask);
        static bool isContactCompatible(const ConferenceServer & server, const shared_ptr<ChatRoom> &cr, const string &specs);
        static string getDeviceName(const shared_ptr<ExtendedContact> &ec);
    };
}

}
