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

#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include <sofia-sip/auth_module.h>

#include <flexisip/auth-status.hh>

namespace flexisip {

/**
 * @brief Interface for authentication modules.
 * @note This class is a plain C++ wrapper of SofiaSip's auth_mod_t
 * object. Please look at http://sofia-sip.sourceforge.net/refdocs/iptsec/auth__module_8h.html
 * for a complete documentation.
 */
class AuthModule {
public:
	AuthModule(su_root_t *root, std::unordered_map<std::string, std::string> params);
	virtual ~AuthModule() = default;

	su_root_t *getRoot() const noexcept {return mRoot;}

	/**
	 * These methods are C++ version of public method of auth_mod_t API. To find the associated
	 * SofiaSip function, just prefix the name of the method by "auth_mod_" e.g. verify() -> auth_mod_verify().
	 */
	void verify(AuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach);
	void challenge(AuthStatus &as, auth_challenger_t const *ach) {if (ach) onChallenge(as, ach);}
	void authorize(AuthStatus &as, auth_challenger_t const *ach) {challenge(as, ach);}
	void cancel(AuthStatus &as) {onCancel(as);}

protected:
	virtual void onCheck(AuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach) = 0;
	virtual void onChallenge(AuthStatus &as, auth_challenger_t const *ach) = 0;
	virtual void onCancel(AuthStatus &as) = 0;

	// attributes
	su_root_t *mRoot = nullptr;
	std::string am_realm{};		/**< Our realm */
	std::string am_opaque{};		/**< Opaque identification data */
	std::string am_gssapi_data; /**< NTLM data */
	std::string am_targetname;	/**< NTLM target name */
	std::vector<std::string> am_allow{"ACK", "BYE", "CANCEL"};		/**< Methods to allow without authentication */
	std::string  am_algorithm{"MD5"};	/**< Defauilt algorithm */
	std::string am_qop{};			/**< Default qop (quality-of-protection) */
	unsigned am_expires = 60 * 60;		/**< Nonce lifetime */
	unsigned am_next_exp = 5 * 60;		/**< Next nonce lifetime */
	unsigned am_blacklist = 5;		/**< Extra delay if bad credentials. */
	bool am_forbidden = false;	/**< Respond with 403 if bad credentials */
	bool am_anonymous = false;	/**< Allow anonymous access */
	bool am_challenge;	/**< Challenge even if successful */
	bool am_nextnonce = true;	/**< Send next nonce in responses */
	bool am_mutual = false;		/**< Mutual authentication */
	bool am_fake = false;		/**< Fake authentication */
	unsigned am_count; /**< Nonce counter */
	bool am_max_ncount = false; /**< If nonzero, challenge with new nonce after ncount */
};

}
