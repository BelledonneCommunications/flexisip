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

#include <memory>

#include <sofia-sip/nta.h>

#include "flexisip/sofia-wrapper/msg-sip.hh"

namespace sofiasip {

/**
 * A class that represent an outgoing SIP transaction.
 * It is created by the NtaAgent when a initial request is sent on the network.
 */
class NtaOutgoingTransaction {
public:
	/**
	 * Returns the status of the last received response, or zero if no response has been received.
	 */
	int getStatus() const noexcept {
		return nta_outgoing_status(mNativePtr);
	}
	/**
	 * Check whether the transaction is completed i.e. a final response (status >= 200) has been receives.
	 */
	bool isCompleted() const noexcept {
		return getStatus() >= 200;
	}
	/**
	 * Return a pointer to the message of the last received response.
	 * The pointer may be null if no response has been received.
	 */
	std::shared_ptr<const MsgSip> getResponse() const noexcept {
		auto* msg = nta_outgoing_getresponse(mNativePtr);
		const auto response = msg ? std::make_shared<const MsgSip>(ownership::Owned(msg)) : nullptr;
		if (mResponse == nullptr or response == nullptr or mResponse->getMsg() != response->getMsg()) {
			mResponse = response;
		}

		return mResponse;
	}

private:
	friend class NtaAgent;

	NtaOutgoingTransaction(nta_outgoing_t* obj) : mNativePtr{obj} {
	}

	nta_outgoing_t* mNativePtr{nullptr};
	mutable std::shared_ptr<const MsgSip> mResponse{nullptr};
};

} // namespace sofiasip
