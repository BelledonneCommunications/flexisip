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

#include "notify-tweaker.hh"

#include <linphone++/address.hh>
#include <linphone++/core.hh>

#include "flexisip/logmanager.hh"

namespace flexisip::b2bua::bridge {

NotifyTweaker::NotifyTweaker(const config::v2::OutgoingNotify& config, linphone::Core& core)
    : mCore(core), mOutboundProxyOverride([&]() -> decltype(mOutboundProxyOverride) {
	      if (config.outboundProxy.empty()) return nullptr;

	      const auto& accountParams = core.createAccountParams();
	      accountParams->enableRegister(false);
	      const auto& route = core.createAddress(config.outboundProxy);
	      if (!route) {
		      SLOGE << "NotifyTweaker::NotifyTweaker : bad outbound proxy format [" << config.outboundProxy << "]";
	      } else {
		      accountParams->setServerAddress(route);
		      accountParams->setRoutesAddresses({route});
	      }
	      const auto account = core.createAccount(accountParams);
	      core.addAccount(account);
	      return account;
      }()) {
}

std::shared_ptr<linphone::Account> NotifyTweaker::getAccountForNotifySending(const flexisip::SipUri& uri) const {
	if (!mOutboundProxyOverride) return nullptr;

	auto newAccountParams = mOutboundProxyOverride->getParams()->clone();
	newAccountParams->setIdentityAddress(mCore.createAddress(uri.str()));
	mOutboundProxyOverride->setParams(newAccountParams);

	return mOutboundProxyOverride;
}

} // namespace flexisip::b2bua::bridge