/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <algorithm>
#include <cstring>
#include <sstream>
#include <stdexcept>

#include "flexisip/logmanager.hh"

#include "flexisip/auth-module.hh"

using namespace std;

namespace flexisip {

AuthModule::AuthModule(su_root_t *root, std::unordered_map<std::string, std::string> params) : mRoot{root} {
	auto it = params.find("realm");
	am_realm = it != params.cend() ? move(it->second) : "*";

	it = params.find("opaque");
	if (it != params.cend()) am_opaque = move(it->second);

	it = params.find("expires");
	if (it != params.cend()) am_expires = unsigned(stoul(it->second));

	it = params.find("next_expires");
	if (it != params.cend()) am_next_exp = unsigned(stoul(it->second));

	it = params.find("forbidden");
	if (it != params.cend()) am_forbidden = bool(stoi(it->second));

	it = params.find("qop");
	if (it != params.cend()) am_qop = move(it->second);

	am_nextnonce = (am_algorithm == "MD5" && am_next_exp > 0);
}

void AuthModule::verify(AuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach) {
	if (!ach) return;

	auto wildcardPos = find(am_realm.cbegin(), am_realm.cend(), '*');
	auto host = as.domain();

	/* Initialize per-request realm */
	if (as.domain())
		;
	else if (wildcardPos == am_realm.cend()) {
		as.realm(am_realm.c_str());
	} else if (!host) {
		return; /* Internal error */
	} else if (am_realm == "*") {
		as.realm(host);
	} else {
		/* Replace * with hostpart */
		as.realm( string{am_realm.cbegin(), wildcardPos} + host + string{wildcardPos+1, am_realm.cend()} );
	}

	onCheck(as, credentials, ach);
}

} // namespace flexisip
