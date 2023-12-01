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
#include <queue>

#include <sofia-sip/nth.h>

#include "flexisip/auth/flexisip-auth-module-base.hh"

#include "utils/string-formatter.hh"

namespace flexisip {

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
		Status(const std::shared_ptr<RequestSipEvent>& ev) : FlexisipAuthStatus(ev) {
		}

		const std::string& reason() const {
			return mReasonHeader;
		}
		void reason(const std::string& val) {
			mReasonHeader = val;
		}

		const std::string& pAssertedIdentity() const {
			return mPAssertedIdentity;
		}
		void pAssertedIdentity(const std::string& val) {
			mPAssertedIdentity = val;
		}

		const std::string& fromHeader() const {
			return mFromHeader;
		}
		void fromHeader(const std::string& val) {
			mFromHeader = val;
		}
		void fromHeader(std::string&& val) {
			mFromHeader = std::move(val);
		}

		const std::string& domain() const {
			return mDomain;
		}
		void domain(const std::string& val) {
			mDomain = val;
		}
		void domain(std::string&& val) {
			mDomain = std::move(val);
		}

		const std::string& sipInstance() const {
			return mSipInstance;
		}
		void sipInstance(const std::string& val) {
			mSipInstance = val;
		}
		void sipInstance(std::string&& val) {
			mSipInstance = std::move(val);
		}

		const std::string& uuid() const {
			return mUUID;
		}
		void uuid(const std::string& uuid) {
			mUUID = uuid;
		}
		void uuid(std::string& uuid) {
			mUUID = std::move(uuid);
		}

	private:
		std::string mReasonHeader; /**< [out] Reason header returned by the HTTP server on authentication failure. */
		std::string mPAssertedIdentity; /**< [out] PAssertIdentity header returned by the HTTP server on authentication
		                                   success. */
		std::string mFromHeader;        /**< [in]  Value of From header of the request. */
		std::string mDomain;            /**< [in]  Domain of the From header. */
		std::string mSipInstance;       /**< [in]  Value of the +sip.instance parameter from Contact header. */
		std::string mUUID;              /**< [in]  UUID of the application that is trying to authenticate. */
	};

	ExternalAuthModule(su_root_t* root, const std::string& domain, int nonceExpire, bool qopAuth);
	~ExternalAuthModule() override;

	StringFormatter& getFormatter() {
		return mUriFormatter;
	}

private:
	struct HttpRequestCtx {
		ExternalAuthModule& am;
		FlexisipAuthStatus& as;
		const auth_challenger_t& ach;
		msg_auth_t& creds;

		HttpRequestCtx(ExternalAuthModule& am, FlexisipAuthStatus& as, const auth_challenger_t& ach, msg_auth_t& creds)
		    : am{am}, as{as}, ach{ach}, creds{creds} {
		}
	};

	void checkAuthHeader(FlexisipAuthStatus& as, msg_auth_t* credentials, auth_challenger_t const* ach) override;
	void popAndSendRequest();

	void onHttpResponse(HttpRequestCtx& ctx, nth_client_t* request, const http_t* http);
	std::map<std::string, std::string> parseHttpBody(const std::string& body) const;

	static std::string extractParameter(const Status& as, const msg_auth_t& credentials, const std::string& paramName);
	static int onHttpResponseCb(nth_client_magic_t* magic, nth_client_t* request, const http_t* http) noexcept;
	static std::string toString(const http_payload_t* httpPayload);
	static bool validSipCode(int sipCode);

	nth_engine_t* mEngine{nullptr};
	HttpUriFormatter mUriFormatter{};
	std::queue<std::unique_ptr<HttpRequestCtx>> pendingAuthRequests{};
	bool mWaitingForResponse{false};

	static std::array<int, 4> sValidSipCodes;
};

} // namespace flexisip
