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

#include <functional>

#include "sofia-sip/auth_module.h"

#include "flexisip/event.hh"
#include "flexisip/sofia-wrapper/auth-status.hh"

namespace flexisip {
/**
 * Interface to be implemented by the authentication schemes.
 **/

class AuthScheme {
public:
	enum class State { Inapplicable, Pending, Done };
	using ChallengeResult = RequestSipEvent::AuthResult::ChallengeResult;

	virtual ~AuthScheme() = default;
	virtual std::string schemeType() const = 0;
	virtual void challenge(AuthStatus& as, const auth_challenger_t* ach) = 0;
	virtual State check(const msg_auth_t* credentials, std::function<void(ChallengeResult&&)>&& onResult) = 0;
};
} // namespace flexisip