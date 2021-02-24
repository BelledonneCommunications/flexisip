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

#include "flexisip/auth/flexisip-auth-module-base.hh"

#include "utils/string-formater.hh"

namespace flexisip {

/**
 * Authentication module that delegates the Authorization header validation to
 * an external HTTP server.
 */
class ExternalAuthModule : public AuthModuleBase {
public:
	/**
	 * Specialization of FlexisipAuthStatus dedicated to ExternalAuthModule.
	 */
	class Status : public AuthStatus {
	public:
		Status(const std::shared_ptr<RequestSipEvent> &ev) : AuthStatus(ev) {}

		const std::string &reason() const {return mReasonHeader;}
		template <typename T>
		void reason(T &&val) {mReasonHeader = std::forward<T>(val);}

		const std::string &pAssertedIdentity() const {return mPAssertedIdentity;}
		template <typename T>
		void pAssertedIdentity(T &&val) {mPAssertedIdentity = std::forward<T>(val);}

		const std::string &fromHeader() const {return mFromHeader;}
		template <typename T>
		void fromHeader(T &&val) {mFromHeader = std::forward<T>(val);}

		const std::string &domain() const {return mDomain;}
		template <typename T>
		void domain(T &&val) {mDomain = std::forward<T>(val);}

		const std::string &sipInstance() const {return mSipInstance;}
		template <typename T>
		void sipInstance(T &&val) {mSipInstance = std::forward<T>(val);}

		const std::string &uuid() const {return mUUID;}
		template <typename T>
		void uuid(T &&uuid) {mUUID = std::forward<T>(uuid);}

	private:
		std::string mReasonHeader{};      /**< [out] Reason header returned by the HTTP server on authentication failure. */
		std::string mPAssertedIdentity{}; /**< [out] PAssertIdentity header returned by the HTTP server on authentication success. */
		std::string mFromHeader{};        /**< [in]  Value of From header of the request. */
		std::string mDomain{};            /**< [in]  Domain of the From header. */
		std::string mSipInstance{};       /**< [in]  Value of the +sip.instance parameter from Contact header. */
		std::string mUUID{};              /**< [in]  UUID of the application that is trying to authenticate. */
	};

	ExternalAuthModule(su_root_t *root, int nonceExpire, bool qopAuth);
	~ExternalAuthModule() override;

	StringFormater &getFormater() {return mUriFormater;}

private:
	struct HttpRequestCtx {
		HttpRequestCtx(ExternalAuthModule &am, const std::shared_ptr<ExternalAuthModule::Status> &as, const auth_challenger_t &ach):
			am{am}, as{as}, ach{ach} {}

		ExternalAuthModule &am;
		std::shared_ptr<ExternalAuthModule::Status> as{};
		const auth_challenger_t &ach;
	};

	void checkAuthHeader(const std::shared_ptr<AuthStatus> &as, msg_auth_t &credentials, const auth_challenger_t &ach) override;

	void onHttpResponse(HttpRequestCtx &ctx, nth_client_t *request, const http_t *http);
	std::map<std::string, std::string> parseHttpBody(const std::string &body) const;

	static std::string extractParameter(const Status &as, const msg_auth_t &credentials, const std::string &paramName);
	static int onHttpResponseCb(nth_client_magic_t *magic, nth_client_t *request, const http_t *http) noexcept;
	static std::string toString(const http_payload_t *httpPayload);
	static bool validSipCode(int sipCode);

	nth_engine_t *mEngine = nullptr;
	HttpUriFormater mUriFormater{};

	static std::array<int, 4> sValidSipCodes;
};

}
