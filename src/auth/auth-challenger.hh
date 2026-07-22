/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include <memory>
#include <string>

#include <sofia-sip/sip_extra.h>

#include "flexisip/sofia-wrapper/auth-status.hh"

namespace flexisip {

class AuthChallenger {
public:
	virtual ~AuthChallenger() = default;

	virtual std::shared_ptr<AuthStatus> challenge(sip_method_t method, const std::string& domain) const = 0;

protected:
	static std::pair<std::shared_ptr<AuthStatus>, const auth_challenger_t&>
	makeAuthStatusAndChallenger(sip_method_t method);
};

} // namespace flexisip