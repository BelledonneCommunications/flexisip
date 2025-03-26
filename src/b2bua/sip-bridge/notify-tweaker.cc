/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "exceptions/bad-configuration.hh"
#include "flexisip/logmanager.hh"
#include "linphone++/account_params.hh"
#include "linphone++/address.hh"
#include "linphone++/core.hh"
#include "linphone++/factory.hh"

namespace flexisip::b2bua::bridge {

NotifyTweaker::NotifyTweaker(const config::v2::OutgoingNotify& config, linphone::Core& core)
    : mOutboundProxyOverride([&]() -> decltype(mOutboundProxyOverride) {
	      if (config.outboundProxy.empty()) return nullptr;

	      const auto& accountParams = core.createAccountParams();
	      accountParams->enableRegister(false);
	      const auto& route = linphone::Factory::get()->createAddress(config.outboundProxy);
	      if (!route)
		      throw BadConfiguration{
		          "invalid outbound proxy SIP URI set in provider configuration for outgoing NOTIFY requests: " +
		          config.outboundProxy};

	      accountParams->setServerAddress(route);
	      accountParams->setRoutesAddresses({route});

	      const auto account = core.createAccount(accountParams);
	      core.addAccount(account);
	      return account;
      }()) {
}

std::shared_ptr<linphone::Account> NotifyTweaker::getAccountForNotifySending(const flexisip::SipUri& uri) const {
	if (!mOutboundProxyOverride) return nullptr;

	auto newAccountParams = mOutboundProxyOverride->getParams()->clone();
	newAccountParams->setIdentityAddress(linphone::Factory::get()->createAddress(uri.str()));
	mOutboundProxyOverride->setParams(newAccountParams);

	return mOutboundProxyOverride;
}

} // namespace flexisip::b2bua::bridge