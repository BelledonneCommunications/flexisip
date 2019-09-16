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

#include "authdb.hh"
#include "flexisip-auth-module-base.hh"
#include "flexisip-auth-status.hh"
#include "nonce-store.hh"
#include "utils/digest.hh"

namespace flexisip {

/**
 * Authentication module using a user database to validate the Authorization header.
 */
class FlexisipAuthModule : public FlexisipAuthModuleBase {
public:
	using PasswordFetchResultCb = std::function<void(bool)>;

	FlexisipAuthModule(su_root_t *root, const std::string &domain, const std::string &algo): FlexisipAuthModuleBase(root, domain, algo) {}
	FlexisipAuthModule(su_root_t *root, const std::string &domain, const std::string &algo, int nonceExpire): FlexisipAuthModuleBase(root, domain, algo, nonceExpire) {}
	~FlexisipAuthModule() override = default;

	void setOnPasswordFetchResultCb(const PasswordFetchResultCb &cb) {mPassworFetchResultCb = cb;}

private:
	class AuthenticationListener : public AuthDbListener {
	public:
		AuthenticationListener(FlexisipAuthModule &am, FlexisipAuthStatus &as, const auth_challenger_t &ach, const auth_response_t &ar): mAm(am), mAs(as), mAch(ach), mAr(ar) {}
		~AuthenticationListener() override = default;

		FlexisipAuthStatus &authStatus() const {return mAs;}
		const auth_challenger_t &challenger() const {return mAch;}
		auth_response_t *response() {return &mAr;}

		std::string password() const {return mPassword;}
		AuthDbResult result() const {return mResult;}

		void onResult(AuthDbResult result, const std::string &passwd) override;
		void onResult(AuthDbResult result, const std::vector<passwd_algo_t> &passwd) override;
		void finishVerifyAlgos(const std::vector<passwd_algo_t> &pass) override;

	private:
		static void main_thread_async_response_cb(su_root_magic_t *rm, su_msg_r msg, void *u);

		friend class Authentication;
		FlexisipAuthModule &mAm;
		FlexisipAuthStatus &mAs;
		const auth_challenger_t &mAch;
		auth_response_t mAr;
		AuthDbResult mResult;
		std::string mPassword;
	};

	void checkAuthHeader(FlexisipAuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach) override;
	void loadPassword(const FlexisipAuthStatus &as) override;

	void processResponse(AuthenticationListener &listener);
	void checkPassword(FlexisipAuthStatus &as, const auth_challenger_t &ach, auth_response_t &ar, const char *password);
	int checkPasswordForAlgorithm(FlexisipAuthStatus &as, auth_response_t &ar, const char *password);

	static std::string auth_digest_a1_for_algorithm(Digest &algo, const auth_response_t *ar, const std::string &secret);
	static std::string auth_digest_a1sess_for_algorithm(Digest &algo, const auth_response_t *ar, const std::string &ha1);
	static std::string auth_digest_response_for_algorithm(Digest &algo, ::auth_response_t *ar, char const *method_name, void const *data, isize_t dlen, const std::string &ha1);

	PasswordFetchResultCb mPassworFetchResultCb;
};

}
