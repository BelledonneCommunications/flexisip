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

#include <flexisip/auth-module.hh>
#include "flexisip-auth-status.hh"
#include "nonce-store.hh"

namespace flexisip {

/**
 * @brief Base class for all authentication modules used by Flexisip.
 *
 * This implementation of AuthModule allows to do HTTP-like authentication
 * of SIP requests as described in RFC 3261 §22.
 */
class FlexisipAuthModuleBase : public AuthModule {
public:
	/**
	 * @brief Instantiate a new authentication module without QOP authentication feature.
	 * @param[in] root Event loop which the module will be working on.
	 * @param[in] domain The domain name which the module is in charge of.
	 * @param[in] algo The digest algorithm to use. Only "MD5" and "SHA-256" are supported.
	 */
	FlexisipAuthModuleBase(su_root_t *root, const std::string &domain);
	/**
	 * @brief Instantiate a new authentication module with QOP authentication feature enabled.
	 * @param[in] nonceExpire Validity period for a nonce in seconds.
	 */
	FlexisipAuthModuleBase(su_root_t *root, const std::string &domain, int nonceExpire);
	~FlexisipAuthModuleBase() override = default;

	NonceStore &nonceStore() {return mNonceStore;}

protected:
	void onCheck(AuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach) override;
	void onChallenge(AuthStatus &as, auth_challenger_t const *ach) override;
	void onCancel(AuthStatus &as) override;

	/**
	 * This method is called each time the module want to authenticate an Authorization header.
	 * The result of the authentication must be store in 'status' attribute of 'as' parameter as
	 * described in documentation of auth_mod_verify() function.
	 *
	 * @param[in,out] as The context on the authentication. It is also used to return the result.
	 * @param[in] credentials The authorization header to validate.
	 */
	virtual void checkAuthHeader(FlexisipAuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach) = 0;
	/**
	 * This function is called when the module is validating a request that doesn't have any authorization header.
	 * It allows implementations based on password database to load the password in cache in order to be already fetched
	 * once the user send a request containing the Authorization header. The default implementation of this method does nothing.
	 */
	virtual void loadPassword(const FlexisipAuthStatus &as) = 0;

	void finish(FlexisipAuthStatus &as);
	void onError(FlexisipAuthStatus &as);

	NonceStore mNonceStore;
	bool mDisableQOPAuth = false;
	bool mImmediateRetrievePass = true;
};

}
