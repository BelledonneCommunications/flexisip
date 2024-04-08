/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <linphone++/account.hh>

#include "accounts/account.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "utils/string-interpolation/preprocessed-interpolated-string.hh"

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
