/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <list>
#include <optional>
#include <string>
#include <unordered_map>

#include "auth/auth-scheme.hh"
#include "flexisip/sofia-wrapper/auth-status.hh"

namespace flexisip {

/**
 * Class that implements the bearer scheme.
 **/
class Bearer : public AuthScheme {
public:
	enum class PubKeyType {
		file,
		url,
		wellknown,
	};
	struct BearerParams {
		std::string issuer;
		std::string realm;
		std::list<std::string> scope;
		std::string idClaimer;
		PubKeyType keyType;
		std::string keyPath;
	};

	Bearer(const BearerParams& params);
	std::string schemeType() const override;
	void challenge(AuthStatus& as, const auth_challenger_t* ach) override;
	std::optional<RequestSipEvent::AuthResult::ChallengeResult> check(const msg_auth_t* credentials) override;

private:
	BearerParams mParams;
	std::unordered_map<std::string, std::string> mPubKeys;
};
} // namespace flexisip
