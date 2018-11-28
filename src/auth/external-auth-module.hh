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

#include <sofia-sip/nth.h>

#include "flexisip-auth-module-base.hh"
#include "utils/string-formater.hh"

class ExternalAuthModule : public FlexisipAuthModuleBase {
public:
	class Status : public FlexisipAuthStatus {
	public:
		const std::string &reason() const {return mReasonHeader;}
		void reason(const std::string &val) {mReasonHeader = val;}

		const std::string &pAssertedIdentity() const {return mPAssertedIdentity;}
		void pAssertedIdentity(const std::string &val) {mPAssertedIdentity = val;}

		std::string fromHeader() const {return mFromHeader;}
		void fromHeader(const std::string &val) {mFromHeader = val;}
		void fromHeader(std::string &&val) {mFromHeader = val;}

		std::string domain() const {return mDomain;}
		void domain(const std::string &val) {mDomain = val;}
		void domain(std::string &&val) {mDomain = val;}

		std::string sipInstance() const {return mSipInstance;}
		void sipInstance(const std::string &val) {mSipInstance = val;}
		void sipInstance(std::string &&val) {mSipInstance = val;}

	private:
		std::string mReasonHeader;
		std::string mPAssertedIdentity;
		std::string mFromHeader;
		std::string mDomain;
		std::string mSipInstance;
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
	std::map<std::string, std::string> splitCommaSeparatedKeyValuesList(const std::string &kvList) const;
	void onHttpResponse(FlexisipAuthStatus &as, nth_client_t *request, const http_t *http);
	std::map<std::string, std::string> parseHttpBody(const std::string &body) const;

	static int onHttpResponseCb(nth_client_magic_t *magic, nth_client_t *request, const http_t *http) noexcept;
	static std::string toString(const http_payload_t *httpPayload);
	static bool validSipCode(int sipCode);

	nth_engine_t *mEngine = nullptr;
	StringFormater mUriFormater;

	static std::array<int, 4> sValidSipCodes;
};
