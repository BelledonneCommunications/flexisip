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

#pragma once

#include "accounts/account.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "b2bua/sip-bridge/linphone-call-context.hh"
#include "linphone++/account.hh"
#include "utils/string-interpolation/template-formatter.hh"

namespace flexisip::b2bua::bridge {

class InviteTweaker {
public:
	using StringTemplate = utils::string_interpolation::TemplateFormatter<const LinphoneCallContext&, const Account&>;

	explicit InviteTweaker(const config::v2::OutgoingInvite&, linphone::Core&);

	/**
	 * Renders the To and From headers with the account selected for the outgoing call.
	 *
	 * @throws InvalidAddress if the To or From templates resolve to an invalid URI
	 *
	 * @returns the tweaked To address.
	 */
	std::shared_ptr<linphone::Address>
	tweakInvite(const LinphoneCallContext&, const Account&, linphone::CallParams&) const;

private:
	// The address to send the INVITE to.
	StringTemplate mToHeader;
	StringTemplate mFromHeader;
	// Workaround: As of 2024-05-21 and SDK 5.3.44, linphone::CallParams do not allow to override the route(s) used in
	// an INVITE request, so we use a surrogate account instead.
	std::shared_ptr<linphone::Account> mOutboundProxyOverride;
	std::optional<bool> mAvpfOverride;
	std::optional<linphone::MediaEncryption> mEncryptionOverride;
};

} // namespace flexisip::b2bua::bridge