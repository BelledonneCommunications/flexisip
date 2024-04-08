/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
