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

#pragma once

#include <optional>
#include <variant>

#include <linphone++/account.hh>
#include <linphone++/call.hh>

#include "b2bua-core.hh"
#include "flexisip/utils/sip-uri.hh"

namespace flexisip::b2bua {

/**
 * @brief Execute specific operations when bridging calls.
 */
class Application {
public:
	using DeclineCall = linphone::Reason;
	using InviteAddress = std::shared_ptr<const linphone::Address>;
	using ActionToTake = std::variant<DeclineCall, InviteAddress>;
	using NotifyDestination = std::pair<const flexisip::SipUri, std::shared_ptr<linphone::Account>>;

	virtual ~Application() = default;

	/**
	 * @brief Initialize B2BUA server application.
	 */
	virtual void init(const std::shared_ptr<B2buaCore>& core, const ConfigManager& cfg) = 0;

	/**
	 * @brief Run some business logic before placing the outgoing call.
	 *
	 * @param[in]     incomingCall       the call that triggered the server
	 * @param[inout]  outgoingCallParams the params of the outgoing call to place (modified according to the business
	 *                                   logic of the application)
	 *
	 * @return a reason to abort the bridging and decline the incoming call, none if the call should go through.
	 **/
	virtual ActionToTake onCallCreate(const linphone::Call& incomingCall, linphone::CallParams& outgoingCallParams) = 0;

	/**
	 * @brief Run some business logic before transferring the call.
	 *
	 * @param[in] call call that received the REFER request
	 */
	virtual std::shared_ptr<const linphone::Address> onTransfer(const linphone::Call& call) {
		return call.getReferToAddress();
	}

	/**
	 * @brief Execute a specific operation once a call has ended.
	 */
	virtual void onCallEnd(const linphone::Call&) {
	}

	/**
	 * @brief Execute a specific operation upon receiving a SUBSCRIBE request.
	 *
	 * @warning not supported yet
	 *
	 * @return linphone::Reason::NotAcceptable
	 */
	virtual ActionToTake onSubscribe(const linphone::Event&, const std::string&) {
		return linphone::Reason::NotAcceptable;
	}

	virtual std::optional<NotifyDestination> onNotifyToBeSent(const linphone::Event&) {
		return std::nullopt;
	}
};

} // namespace flexisip::b2bua