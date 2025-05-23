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

#include "b2bua/b2bua-server.hh"
#include "linphone++/call_listener.hh"

namespace flexisip::b2bua {

/**
 * @brief Call listener needed in case of call transfer. Allows to forward NOTIFY requests to peer call.
 */
class CallTransferListener : public linphone::CallListener {
public:
	explicit CallTransferListener(const std::weak_ptr<linphone::Call>& peerCall) : mPeerCall(peerCall) {
	}
	void onTransferStateChanged(const std::shared_ptr<linphone::Call>& call, linphone::Call::State state) override;

private:
	static constexpr std::string_view mLogPrefix{"CallTransferListener"};

	/**
	 * @brief Send NOTIFY request to peer call.
	 *
	 * @param[in] body request body, example: "SIP/2.0 100 Trying\\r\\n"
	 */
	void sendNotify(const std::string& body);

	std::weak_ptr<linphone::Call> mPeerCall;
};

} // namespace flexisip::b2bua