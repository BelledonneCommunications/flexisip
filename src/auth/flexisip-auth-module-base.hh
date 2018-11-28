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

#include "auth-module.hh"
#include "flexisip-auth-status.hh"
#include "nonce-store.hh"

class FlexisipAuthModuleBase : public AuthModule {
public:
	FlexisipAuthModuleBase(su_root_t *root, const std::string &domain, const std::string &algo);
	FlexisipAuthModuleBase(su_root_t *root, const std::string &domain, const std::string &algo, int nonceExpire);
	~FlexisipAuthModuleBase() override = default;

	NonceStore &nonceStore() {return mNonceStore;}

protected:
	virtual void checkAuthHeader(FlexisipAuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach) = 0;
	virtual void loadPassword(const FlexisipAuthStatus &as) = 0;

	void finish(FlexisipAuthStatus &as);
	void onError(FlexisipAuthStatus &as);

	NonceStore mNonceStore;
	bool mDisableQOPAuth = false;
	bool mImmediateRetrievePass = true;

private:
	void onCheck(AuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach) override;
	void onChallenge(AuthStatus &as, auth_challenger_t const *ach) override;
	void onCancel(AuthStatus &as) override;
};
