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

#include "presentity-presence-information-listener.hh"

#define ETAG_SIZE 8
using namespace std;
using namespace std::chrono;

namespace flexisip {

bool PresentityPresenceInformationListener::extendedNotifyEnabled() const {
	return mExtendedNotify || bypassEnabled();
}
void PresentityPresenceInformationListener::enableExtendedNotify(bool enable) {
	mExtendedNotify = enable;
}
bool PresentityPresenceInformationListener::bypassEnabled() const {
	return mBypassEnabled;
}
void PresentityPresenceInformationListener::enableBypass(bool enable) {
	mBypassEnabled = enable;
}

} /* namespace flexisip */
