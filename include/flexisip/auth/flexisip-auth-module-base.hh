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

#include <string>
#include <vector>

#include <sofia-sip/auth_digest.h>
#include <sofia-sip/auth_module.h>
#include <sofia-sip/msg_types.h>
#include <sofia-sip/su_wait.h>

#include "flexisip-auth-status.hh"
#include "nonce-store.hh"

namespace flexisip {

/**
 * @brief Base class for all authentication modules used by Flexisip.
 *
 * This implementation of AuthModule allows to do HTTP-like authentication
 * of SIP requests as described in RFC 3261 §22.
 */
class FlexisipAuthModuleBase {
public:
	/**
	 * @brief Instantiate a new authentication module without QOP authentication feature.
	 * @param[in] root Event loop which the module will be working on.
	 * @param[in] domain The domain name which the module is in charge of.
	 * @param[in] nonceExpire Validity period for a nonce in seconds.
	 * @param[in] qopAuth Setting true allows clients to use the same nonce for successive authentication.
	 */
	FlexisipAuthModuleBase(su_root_t *root, const std::string &domain, unsigned nonceExpire, bool qopAuth);
	virtual ~FlexisipAuthModuleBase() = default;

	NonceStore &nonceStore() {return mNonceStore;}
	su_root_t *getRoot() const noexcept {return mRoot;}

	void verify(FlexisipAuthStatus &as, msg_auth_t &credentials, const auth_challenger_t &ach);
	virtual void challenge(FlexisipAuthStatus &as, const auth_challenger_t &ach);

protected:
	struct Nonce {
		msg_time_t issued;
		uint32_t count;
		uint16_t nextnonce;
		uint8_t digest[6];
	};

	/**
	 * This method is called each time the module want to authenticate an Authorization header.
	 * The result of the authentication must be store in 'status' attribute of 'as' parameter as
	 * described in documentation of auth_mod_verify() function.
	 *
	 * @param[in,out] as The context on the authentication. It is also used to return the result.
	 * @param[in] credentials The authorization header to validate.
	 */
	virtual void checkAuthHeader(FlexisipAuthStatus &as, msg_auth_t &credentials, const auth_challenger_t &ach) = 0;

	void notify(FlexisipAuthStatus &as);
	void onError(FlexisipAuthStatus &as);

	std::string generateDigestNonce(bool nextnonce, msg_time_t now);

	// Attributes
	std::string am_realm{};		/**< Our realm */
	std::string am_opaque{"+GNywA=="};		/**< Opaque identification data */
	std::string am_qop{};			/**< Default qop (quality-of-protection) */
	unsigned am_expires = 60 * 60;		/**< Nonce lifetime */
	unsigned am_blacklist = 5;		/**< Extra delay if bad credentials. */
	bool am_forbidden = true;	/**< Respond with 403 if bad credentials */
	bool am_nextnonce = true;	/**< Send next nonce in responses */
	unsigned am_count = 0; /**< Nonce counter */
	unsigned am_max_ncount = 0; /**< If nonzero, challenge with new nonce after ncount */

	su_root_t *mRoot = nullptr;
	NonceStore mNonceStore{};
	bool mQOPAuth = false;
};

}
