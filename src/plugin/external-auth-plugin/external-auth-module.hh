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

#include <array>

#include <sofia-sip/nth.h>

#include "auth/flexisip-auth-module-base.hh"
#include "utils/string-formater.hh"


/**
 * Authentication module that delegates the Authorization header validation to
 * an external HTTP server.
 */
class ExternalAuthModule : public FlexisipAuthModuleBase {
public:
	/**
	 * Specialization of FlexisipAuthStatus dedicated to ExternalAuthModule.
	 */
	class Status : public FlexisipAuthStatus {
	public:
		const std::string &reason() const {return mReasonHeader;}
		void reason(const std::string &val) {mReasonHeader = val;}

		const std::string &pAssertedIdentity() const {return mPAssertedIdentity;}
		void pAssertedIdentity(const std::string &val) {mPAssertedIdentity = val;}

		const std::string &fromHeader() const {return mFromHeader;}
		void fromHeader(const std::string &val) {mFromHeader = val;}
		void fromHeader(std::string &&val) {mFromHeader = val;}

		const std::string &domain() const {return mDomain;}
		void domain(const std::string &val) {mDomain = val;}
		void domain(std::string &&val) {mDomain = val;}

		const std::string &sipInstance() const {return mSipInstance;}
		void sipInstance(const std::string &val) {mSipInstance = val;}
		void sipInstance(std::string &&val) {mSipInstance = val;}

	private:
		std::string mReasonHeader;      /**< [out] Reason header returned by the HTTP server on authentication failure. */
		std::string mPAssertedIdentity; /**< [out] PAssertIdentity header returned by the HTTP server on authentication success. */
		std::string mFromHeader;        /**< [in]  Value of From header of the request. */
		std::string mDomain;            /**< [in]  Domain of the From header. */
		std::string mSipInstance;       /**< [in]  Value of the +sip.instance parameter from Contact header. */
	};

	ExternalAuthModule(su_root_t *root, const std::string &domain, const std::string &algo);
	ExternalAuthModule(su_root_t *root, const std::string &domain, const std::string &algo, int nonceExpire);
	~ExternalAuthModule() override;

	StringFormater &getFormater() {return mUriFormater;}

private:
	struct HttpRequestCtx {
		ExternalAuthModule &am;
		FlexisipAuthStatus &as;
	};

	void checkAuthHeader(FlexisipAuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach) override;
	void loadPassword(const FlexisipAuthStatus &as) override;

	std::map<std::string, std::string> extractParameters(const Status &as, const msg_auth_t &credentials) const;
	std::map<std::string, std::string> extractCredentialParameters(const msg_param_t *params) const;
	void onHttpResponse(FlexisipAuthStatus &as, nth_client_t *request, const http_t *http);
	std::map<std::string, std::string> parseHttpBody(const std::string &body) const;

	static int onHttpResponseCb(nth_client_magic_t *magic, nth_client_t *request, const http_t *http) noexcept;
	static std::string toString(const http_payload_t *httpPayload);
	static bool validSipCode(int sipCode);

	nth_engine_t *mEngine = nullptr;
	HttpUriFormater mUriFormater;

	static std::array<int, 4> sValidSipCodes;
};
