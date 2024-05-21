/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <linphone++/account.hh>
#include <linphone++/call.hh>

#include "accounts/account.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "utils/string-interpolation/preprocessed-interpolated-string.hh"

namespace flexisip::b2bua::bridge {

class InviteTweaker {
public:
	using StringTemplate =
	    utils::string_interpolation::PreprocessedInterpolatedString<const linphone::Call&, const Account&>;

	class InvalidAddress : public std::runtime_error {
	public:
		explicit InvalidAddress(const char* headerName, std::string invalidAddress)
		    : std::runtime_error(headerName), mWhat(invalidAddress) {
		}

		const char* what() const noexcept override;

	private:
		mutable std::string mWhat;
	};

	explicit InviteTweaker(const config::v2::OutgoingInvite&, linphone::Core&);

	/* @throws InvalidAddress if the mToHeader or mFromHeader templates resolve to an invalid URI */
	std::shared_ptr<linphone::Address> tweakInvite(const linphone::Call&, const Account&, linphone::CallParams&) const;

private:
	/// The address to send the INVITE to
	StringTemplate mToHeader;
	StringTemplate mFromHeader;
	/// Workaround: As of 2024-05-21 and SDK 5.3.44, linphone::CalParams do not allow to override the route(s) used in
	/// an invite, so we use a surrogate account instead
	std::shared_ptr<linphone::Account> mOutboundProxyOverride;
	std::optional<bool> mAvpfOverride;
	std::optional<linphone::MediaEncryption> mEncryptionOverride;
};

} // namespace flexisip::b2bua::bridge
