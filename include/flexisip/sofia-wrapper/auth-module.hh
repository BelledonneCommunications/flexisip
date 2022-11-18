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

#include <memory>

#include <sofia-sip/auth_module.h>

#include "flexisip/sofia-wrapper/auth-status.hh"

namespace flexisip {

/**
 * @brief Interface for authentication modules.
 * @note This class is a plain C++ wrapper of SofiaSip's auth_mod_t
 * object. Please look at http://sofia-sip.sourceforge.net/refdocs/iptsec/auth__module_8h.html
 * for a complete documentation.
 */
class AuthModule {
public:
	AuthModule(su_root_t* root, tag_type_t, tag_value_t, ...);
	virtual ~AuthModule() {
		auth_mod_destroy(mAm);
	}

	/**
	 * Return a pointer on the underlying SofiaSip's authentication module.
	 * This method is useful if you mean to call a SofiaSip function that needs
	 * an auth_mod_t object as parameter.
	 */
	auth_mod_t* getPtr() const {
		return mAm;
	}

	/**
	 * Event loop which the authentication module is working on.
	 * This has been define on module construction.
	 */
	su_root_t* getRoot() const {
		return mRoot;
	}

	/**
	 * These methods are C++ version of public method of auth_mod_t API. To find the associated
	 * SofiaSip function, just prefix the name of the method by "auth_mod_" e.g. verify() -> auth_mod_verify().
	 */
	void verify(AuthStatus& as, msg_auth_t* credentials, auth_challenger_t const* ach) {
		auth_mod_verify(mAm, as.getPtr(), credentials, ach);
	}
	void challenge(AuthStatus& as, auth_challenger_t const* ach) {
		auth_mod_challenge(mAm, as.getPtr(), ach);
	}
	void authorize(AuthStatus& as, auth_challenger_t const* ach) {
		auth_mod_challenge(mAm, as.getPtr(), ach);
	}
	void cancel(AuthStatus& as) {
		auth_mod_cancel(mAm, as.getPtr());
	}

protected:
	virtual void onCheck(AuthStatus& as, msg_auth_t* credentials, auth_challenger_t const* ach) = 0;
	virtual void onChallenge(AuthStatus& as, auth_challenger_t const* ach) = 0;
	virtual void onCancel(AuthStatus& as) = 0;

	auth_mod_t* mAm = nullptr;

private:
	static void checkCb(auth_mod_t* am, auth_status_t* as, msg_auth_t* auth, auth_challenger_t const* ch) noexcept;
	static void challengeCb(auth_mod_t* am, auth_status_t* as, auth_challenger_t const* ach) noexcept;
	static void cancelCb(auth_mod_t* am, auth_status_t* as) noexcept;

	static void registerScheme();

	su_root_t* mRoot = nullptr;
	static const char* sMethodName;
	static auth_scheme_t sAuthScheme;
	static bool sSchemeRegistered;
};

} // namespace flexisip