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

#include "flexisip/auth/nonce-store.hh"
#include "flexisip/auth/digest-authentifier-base.hh"

#include "authdb.hh"
#include "utils/digest.hh"

namespace flexisip {

/**
 * Authentication module using a user database to validate the Authorization header.
 */
class DigestAuthentifier : public DigestAuthBase {
public:
	using PasswordFetchResultCb = std::function<void(bool)>;

	DigestAuthentifier(su_root_t *root, int nonceExpire, bool qopAuth): DigestAuthBase(root, nonceExpire, qopAuth) {}
	~DigestAuthentifier() override = default;

	void setOnPasswordFetchResultCb(const PasswordFetchResultCb &cb) {mPassworFetchResultCb = cb;}

	void challenge(const std::shared_ptr<AuthStatus> &as) override;

private:
	class GenericAuthListener : public AuthDbListener {
	public:
		GenericAuthListener(su_root_t *root, const AuthDbBackend::ResultCb &func): mRoot(root), mFunc(func) {}
		GenericAuthListener(const GenericAuthListener &) = default;

		void onResult(AuthDbResult result, const std::string &passwd) override;
		void onResult(AuthDbResult result, const AuthDbBackend::PwList &passwd) override;

	private:
		static void main_thread_async_response_cb(su_root_magic_t *rm, su_msg_r msg, void *u) noexcept;

		su_root_t *mRoot = nullptr;
		AuthDbBackend::ResultCb mFunc;
		AuthDbResult mResult = PENDING;
		AuthDbBackend::PwList mPasswords;
	};

	void checkAuthHeader(const std::shared_ptr<AuthStatus> &as, msg_auth_t &credentials) override;

	void processResponse(const std::shared_ptr<AuthStatus> &as, const AuthResponse &ar, AuthDbResult result, const AuthDbBackend::PwList &passwords);
	void checkPassword(const std::shared_ptr<AuthStatus> &as, const AuthResponse &ar, const std::string &password);
	int checkPasswordForAlgorithm(AuthStatus &as, const AuthResponse &ar, std::string ha1);

	void onAccessForbidden(const std::shared_ptr<AuthStatus> &as, std::string phrase = "Forbidden");

	static std::string computeA1(Digest &algo, const AuthResponse &ar, const std::string &secret);
	static std::string computeA1SESS(Digest &algo, const AuthResponse &ar, const std::string &ha1);
	static std::string computeDigestResponse(Digest &algo, const AuthResponse &ar, const std::string &method_name, const void *body, size_t bodyLen, const std::string &ha1);

	int validateDigestNonce(AuthStatus &as, AuthResponse &ar, msg_time_t now);
	void infoDigest(AuthStatus &as);

	// Attributes
	PasswordFetchResultCb mPassworFetchResultCb;
};

}
