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
#include "utils/string-interpolation/template-formatter.hh"

namespace flexisip::b2bua::bridge {

class ReferTweaker {
public:
	// The outgoing-header translation rule the Refer-To header is rendered with.
	enum class HeaderTranslation { To, From };

	using StringTemplate = utils::string_interpolation::TemplateFormatter<const LinphoneCallContext&, const Account&>;

	explicit ReferTweaker(const config::v2::OutgoingInvite&);

	/**
	 * Renders the Refer-To header with the translation rule of either the To or the From outgoing header,
	 * using the given account.
	 *
	 * @return the tweaked Refer-To address.
	 */
	std::shared_ptr<linphone::Address> tweakRefer(const LinphoneCallContext&, const Account&, HeaderTranslation) const;

private:
	StringTemplate mToHeader;
	StringTemplate mFromHeader;
};

} // namespace flexisip::b2bua::bridge