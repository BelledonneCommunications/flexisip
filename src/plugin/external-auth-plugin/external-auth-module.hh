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
	ExternalAuthModule(su_root_t *root, int nonceExpire, bool qopAuth);
	~ExternalAuthModule() override;

	StringFormater &getFormater() {return mUriFormater;}

private:
	struct HttpRequestCtx {
		HttpRequestCtx(ExternalAuthModule &am, const std::shared_ptr<AuthStatus> &as, const auth_challenger_t &ach):
			am{am}, as{as}, ach{ach} {}

		ExternalAuthModule &am;
		std::shared_ptr<AuthStatus> as{};
		const auth_challenger_t &ach;
	};

	void checkAuthHeader(const std::shared_ptr<AuthStatus> &as, msg_auth_t &credentials, const auth_challenger_t &ach) override;

	void onHttpResponse(HttpRequestCtx &ctx, nth_client_t *request, const http_t *http);
	std::map<std::string, std::string> parseHttpBody(const std::string &body) const;

	static std::string extractParameter(const AuthStatus &as, const msg_auth_t &credentials, const std::string &paramName);
	static int onHttpResponseCb(nth_client_magic_t *magic, nth_client_t *request, const http_t *http) noexcept;
	static std::string toString(const http_payload_t *httpPayload);
	static bool validSipCode(int sipCode);

	nth_engine_t *mEngine = nullptr;
	HttpUriFormater mUriFormater{};

	static std::array<int, 4> sValidSipCodes;
};

}
