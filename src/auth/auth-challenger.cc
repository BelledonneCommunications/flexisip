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

#include "auth-challenger.hh"

#include <memory>

#include <sofia-sip/sip_extra.h>
#include <sofia-sip/sip_status.h>

#include "flexisip/sofia-wrapper/auth-status.hh"

using namespace std;

namespace flexisip {

static constexpr auth_challenger_t kRegistrarChallenger{
    401,
    sip_401_Unauthorized,
    sip_www_authenticate_class,
    sip_authentication_info_class,
};
static constexpr auth_challenger_t kProxyChallenger{
    407,
    sip_407_Proxy_auth_required,
    sip_proxy_authenticate_class,
    sip_proxy_authentication_info_class,
};

std::pair<std::shared_ptr<AuthStatus>, const auth_challenger_t&>
AuthChallenger::makeAuthStatusAndChallenger(sip_method_t method) {
	auto status = std::make_shared<AuthStatus>();
	const auto& challenger = method == sip_method_register ? kRegistrarChallenger : kProxyChallenger;
	status->status(challenger.ach_status);
	status->phrase(challenger.ach_phrase);
	return {status, challenger};
}

} // namespace flexisip