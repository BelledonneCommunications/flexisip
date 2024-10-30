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

#include <linphone++/account.hh>

#include "accounts/account.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"

namespace flexisip::b2bua::bridge {

class NotifyTweaker {
public:
	explicit NotifyTweaker(const config::v2::OutgoingNotify&, linphone::Core&);

	std::shared_ptr<linphone::Account> getAccountForNotifySending(const flexisip::SipUri& uri) const;

private:
	linphone::Core& mCore;
	std::shared_ptr<linphone::Account> mOutboundProxyOverride;
};

} // namespace flexisip::b2bua::bridge