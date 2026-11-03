/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "linphone++/address.hh"
#include "linphone++/call.hh"
#include "linphone++/call_log.hh"
#include "linphone++/call_params.hh"
#include "linphone++/factory.hh"

namespace flexisip::b2bua::bridge {

/**
 * The subset of a call the outgoing request templates are rendered from.
 */
struct LinphoneCallContext {
	std::shared_ptr<const linphone::Address> to;
	std::shared_ptr<const linphone::Address> from;
	std::shared_ptr<const linphone::Address> requestUri;
	std::string callId;

	/**
	 * Extract the template-rendering fields from an incoming call.
	 */
	static LinphoneCallContext fromCall(const linphone::Call& call) {
		return {
		    .to = call.getToAddress(),
		    .from = call.getRemoteAddress(),
		    .requestUri = call.getRequestAddress(),
		    .callId = call.getCallLog()->getCallId(),
		};
	}

	/**
	 * Extract the template-rendering fields from a call for which a REFER request is received. The To, From and
	 * request-URI fields all designate the transfer target: any template mention of 'to', 'from' or 'requestUri'
	 * resolves to the Refer-To data of the transfer.
	 */
	static LinphoneCallContext fromCallForRefer(const linphone::Call& call) {
		return {
		    .to = call.getReferToAddress(),
		    .from = call.getReferToAddress(),
		    .requestUri = call.getReferToAddress(),
		    .callId = call.getCallLog()->getCallId(),
		};
	}
};

} // namespace flexisip::b2bua::bridge