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

#include "presence-longterm.hh"

#include <belle-sip/belle-sip.h>

#include "presence/observers/presence-auth-db-listener.hh"
#include "presence/presentity/presentity-presence-information.hh"

using namespace flexisip;
using namespace std;

void PresenceLongterm::onListenerEvent(const std::shared_ptr<PresentityPresenceInformation>& info) const {
	if (!info->hasDefaultElement()) {
		// no presence information know yet, so ask again to the db.
		const belle_sip_uri_t* uri = info->getEntity();
		SLOGD << "No presence info element known yet for " << belle_sip_uri_get_user(uri)
		      << ", checking if this user is already registered";
		mAuthDb->db().getUserWithPhone(belle_sip_uri_get_user(info->getEntity()),
		                               belle_sip_uri_get_host(info->getEntity()),
		                               new PresenceAuthDbListener(mMainLoop, info, mRegistrarDb));
	}
}
void PresenceLongterm::onListenerEvents(list<shared_ptr<PresentityPresenceInformation>>& infos) const {
	list<tuple<string, string, AuthDbListener*>> creds;
	unordered_map<string, shared_ptr<PresentityPresenceInformation>> dInfo;
	for (const shared_ptr<PresentityPresenceInformation>& info : infos) {
		if (!info->hasDefaultElement()) {
			creds.emplace_back(belle_sip_uri_get_user(info->getEntity()), belle_sip_uri_get_host(info->getEntity()),
			                   new PresenceAuthDbListener(mMainLoop, info, mRegistrarDb));
		}
		dInfo.try_emplace(belle_sip_uri_get_user(info->getEntity()), info);
	}
	mAuthDb->db().getUsersWithPhone(creds);
}
