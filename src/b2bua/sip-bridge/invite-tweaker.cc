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

#include "invite-tweaker.hh"

#include <linphone++/address.hh>
#include <linphone++/call_params.hh>
#include <linphone++/core.hh>

#include "exceptions/invalid-address.hh"
#include "flexisip/logmanager.hh"
#include "string-format-fields.hh"

namespace flexisip::b2bua::bridge {
using namespace utils::string_interpolation;

namespace {

const auto kInviteTweakerFields = FieldsOf<linphone::Call const&, Account const&>{
    {
        "incoming",
        resolve(kLinphoneCallFields, [](const auto& call, const auto&) -> const auto& { return call; }),
    },
    {
        "account",
        resolve(kAccountFields, [](const auto&, const auto& account) -> const auto& { return account; }),
    },
};

} // namespace

InviteTweaker::InviteTweaker(const config::v2::OutgoingInvite& config, linphone::Core& core)
    : mToHeader(config.to, kInviteTweakerFields),
      mFromHeader(config.from.empty() ? "{account.uri}" : config.from, kInviteTweakerFields),
      mOutboundProxyOverride([&]() -> decltype(mOutboundProxyOverride) {
	      if (!config.outboundProxy) return nullptr;

	      const auto& accountParams = core.createAccountParams();
	      accountParams->enableRegister(false);
	      const auto& route = linphone::Factory::get()->createAddress(*config.outboundProxy);
	      if (!route) {
		      SLOGE << "InviteTweaker::InviteTweaker : bad outbound proxy format [" << *config.outboundProxy << "]";
	      } else {
		      accountParams->setServerAddress(route);
		      accountParams->setRoutesAddresses({route});
	      }

	      accountParams->setIdentityAddress(
	          linphone::Factory::get()->createAddress("sip:flexisip-b2bua-invite-tweaker@localhost"));
	      const auto account = core.createAccount(accountParams);
	      core.addAccount(account);
	      return account;
      }()),
      mAvpfOverride(config.enableAvpf), mEncryptionOverride(config.mediaEncryption) {
}

std::shared_ptr<linphone::Address> InviteTweaker::tweakInvite(const linphone::Call& incomingCall,
                                                              const Account& account,
                                                              linphone::CallParams& outgoingCallParams) const {
	outgoingCallParams.setAccount(mOutboundProxyOverride ? mOutboundProxyOverride : account.getLinphoneAccount());

	if (const auto& mediaEncryption = mEncryptionOverride) {
		outgoingCallParams.setMediaEncryption(*mediaEncryption);
	}
	if (const auto& enableAvpf = mAvpfOverride) {
		outgoingCallParams.enableAvpf(*enableAvpf);
	}

	const auto fromAddress = mFromHeader.format(incomingCall, account);
	if (!linphone::Factory::get()->createAddress(fromAddress)) throw InvalidAddress("From", fromAddress);

	outgoingCallParams.setFromHeader(fromAddress);

	const auto toAddressStr = mToHeader.format(incomingCall, account);
	const auto toAddress = linphone::Factory::get()->createAddress(toAddressStr);
	if (!toAddress) throw InvalidAddress("To", toAddressStr);

	return toAddress;
}

} // namespace flexisip::b2bua::bridge