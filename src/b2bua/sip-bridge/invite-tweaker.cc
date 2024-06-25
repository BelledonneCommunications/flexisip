/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "invite-tweaker.hh"

#include <linphone++/account_params.hh>
#include <linphone++/address.hh>
#include <linphone++/call_params.hh>
#include <linphone++/core.hh>

#include "b2bua/sip-bridge/string-format-fields.hh"
#include "flexisip/logmanager.hh"

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
	      const auto& route = core.createAddress(*config.outboundProxy);
	      if (!route) {
		      SLOGE << "InviteTweaker::InviteTweaker : bad outbound proxy format [" << *config.outboundProxy << "]";
	      } else {
		      accountParams->setServerAddress(route);
		      accountParams->setRoutesAddresses({route});
	      }
	      accountParams->setIdentityAddress(core.createAddress("sip:flexisip-b2bua-sip-bridge-placeholder@localhost"));
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
	auto& core = *incomingCall.getCore();
	if (!core.createAddress(fromAddress)) throw InvalidAddress("From", fromAddress);

	outgoingCallParams.setFromHeader(fromAddress);

	const auto toAddressStr = mToHeader.format(incomingCall, account);
	const auto toAddress = core.createAddress(toAddressStr);
	if (!toAddress) throw InvalidAddress("To", toAddressStr);

	return toAddress;
}

const char* InviteTweaker::InvalidAddress::what() const noexcept {
	const auto* headerName = std::runtime_error::what();
	const auto& invalidAddress = mWhat;
	auto msg = std::ostringstream();
	msg << "Attempting to send an outgoing invite with an invalid URI in its '" << headerName << "' header: '"
	    << invalidAddress << "'";
	mWhat = msg.str();

	return mWhat.c_str();
}

} // namespace flexisip::b2bua::bridge
