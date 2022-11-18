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

#include <sstream>
#include <stdexcept>

#include "sofia-sip/auth_plugin.h"
#include "sofia-sip/su_tagarg.h"

#include "flexisip/sofia-wrapper/auth-module.hh"

using namespace std;
using namespace flexisip;

struct auth_plugin_t {
	AuthModule* backPtr;
};

struct auth_mod_plugin_t {
	auth_mod_t module[1];
	auth_plugin_t plugin[1];
};

AuthModule::AuthModule(su_root_t* root, tag_type_t tag, tag_value_t value, ...) : mRoot(root) {
	ta_list ta;

	registerScheme();

	ta_start(ta, tag, value);
	mAm = auth_mod_create(root, AUTHTAG_METHOD(sMethodName), ta_tags(ta));
	ta_end(ta);

	if (mAm == nullptr) {
		ostringstream os;
		os << "couldn't create '" << sMethodName << "' authentication module";
		throw logic_error(os.str());
	}

	(AUTH_PLUGIN(mAm))->backPtr = this;
}

void AuthModule::checkCb(auth_mod_t* am, auth_status_t* as, msg_auth_t* auth, auth_challenger_t const* ch) noexcept {
	AuthStatus& authStatus = *reinterpret_cast<AuthStatus*>(as->as_plugin);
	(AUTH_PLUGIN(am))->backPtr->onCheck(authStatus, auth, ch);
}

void AuthModule::challengeCb(auth_mod_t* am, auth_status_t* as, auth_challenger_t const* ach) noexcept {
	AuthStatus& authStatus = *reinterpret_cast<AuthStatus*>(as->as_plugin);
	(AUTH_PLUGIN(am))->backPtr->onChallenge(authStatus, ach);
}

void AuthModule::cancelCb(auth_mod_t* am, auth_status_t* as) noexcept {
	AuthStatus& authStatus = *reinterpret_cast<AuthStatus*>(as->as_plugin);
	(AUTH_PLUGIN(am))->backPtr->onCancel(authStatus);
}

void AuthModule::registerScheme() {
	if (!sSchemeRegistered) {
		if (auth_mod_register_plugin(&sAuthScheme) != 0) {
			ostringstream os;
			os << "couldn't register '" << sMethodName << "' authentication plugin";
			throw logic_error(os.str());
		}
		sSchemeRegistered = true;
	}
}

const char* AuthModule::sMethodName = "flexisip";

auth_scheme_t AuthModule::sAuthScheme = {
    sMethodName, sizeof(auth_mod_plugin_t), auth_init_default, checkCb, challengeCb, cancelCb, auth_destroy_default};

bool AuthModule::sSchemeRegistered = false;
