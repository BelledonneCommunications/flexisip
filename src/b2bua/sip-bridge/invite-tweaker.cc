/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "invite-tweaker.hh"

#include <linphone++/account_params.hh>
#include <linphone++/address.hh>
#include <linphone++/call_params.hh>
#include <linphone++/core.hh>

#include "b2bua/sip-bridge/variable-substitution.hh"

namespace flexisip::b2bua::bridge {
using namespace utils::string_interpolation;

namespace {
using namespace variable_substitution;

const auto kInviteTweakerFields = FieldsOf<linphone::Call const&, Account const&>{
    {"incoming", resolve(kLinphoneCallFields, [](const auto& call, const auto&) -> const auto& { return call; })},
    {"account", resolve(kAccountFields, [](const auto&, const auto& account) -> const auto& { return account; })},
};

constexpr auto resolver = resolve(kInviteTweakerFields);

} // namespace

InviteTweaker::InviteTweaker(const config::v2::OutgoingInvite& config, linphone::Core& core)
    : mToHeader(InterpolatedString(config.to, "{", "}"), resolver),
      mFromHeader(config.from.empty()
                      ? std::nullopt
                      : decltype(mFromHeader)(StringTemplate(InterpolatedString(config.from, "{", "}"), resolver))),
      mOutboundProxyOverride(config.outboundProxy ? core.createAddress(*config.outboundProxy) : nullptr),
      mAvpfOverride(config.enableAvpf), mEncryptionOverride(config.mediaEncryption) {
}

std::shared_ptr<linphone::Address> InviteTweaker::tweakInvite(const linphone::Call& incomingCall,
                                                              const Account& account,
                                                              linphone::CallParams& outgoingCallParams) const {
	auto linphoneAccount = account.getLinphoneAccount();
	if (mOutboundProxyOverride) {
		const auto& accountParams = linphoneAccount->getParams()->clone();
		accountParams->setServerAddress(mOutboundProxyOverride);
		accountParams->setRoutesAddresses({mOutboundProxyOverride});
		linphoneAccount = linphoneAccount->getCore()->createAccount(accountParams);
	}
	outgoingCallParams.setAccount(linphoneAccount);

	if (const auto& mediaEncryption = mEncryptionOverride) {
		outgoingCallParams.setMediaEncryption(*mediaEncryption);
	}
	if (const auto& enableAvpf = mAvpfOverride) {
		outgoingCallParams.enableAvpf(*enableAvpf);
	}

	auto& core = *incomingCall.getCore();
	if (mFromHeader) {
		const auto fromAddress = mFromHeader->format(incomingCall, account);
		if (!core.createAddress(fromAddress)) throw InvalidAddress("From", fromAddress);

		outgoingCallParams.setFromHeader(fromAddress);
	}
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
