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

#include <linphone++/linphone.hh>

namespace flexisip::tester {

struct MwiCoreStats {
	uint32_t nbSubscribeActive = 0;
	uint32_t nbSubscribeReceived = 0;
	uint32_t nbSubscribeTerminated = 0;
	uint32_t nbMwiReceived = 0;
	uint32_t nbNewMWIVoice = 0;
	uint32_t nbOldMWIVoice = 0;
	uint32_t nbNewUrgentMWIVoice = 0;
	uint32_t nbOldUrgentMWIVoice = 0;
};

class MwiListener : public linphone::CoreListener, public linphone::AccountListener {
public:
	MwiListener() = default;

	MwiListener(const MwiListener& other) = delete;
	MwiListener(MwiListener&& other) = default;

	~MwiListener() = default;

	const MwiCoreStats& getStats() const {
		return mStats;
	};

private:
	// CoreListener
	void onSubscribeReceived(const std::shared_ptr<linphone::Core>& core,
	                         const std::shared_ptr<linphone::Event>& linphoneEvent,
	                         const std::string& subscribeEvent,
	                         const std::shared_ptr<const linphone::Content>& body) override;
	void onSubscriptionStateChanged(const std::shared_ptr<linphone::Core>& core,
	                                const std::shared_ptr<linphone::Event>& linphoneEvent,
	                                linphone::SubscriptionState state) override;
	void onMessageWaitingIndicationChanged(const std::shared_ptr<linphone::Core>&,
	                                       const std::shared_ptr<linphone::Event>&,
	                                       const std::shared_ptr<const linphone::MessageWaitingIndication>&) override {
		// Dummy override to prevent compilation errors (mismatch with onMessageWaitingIndicationChanged from
		// AccountListener)
	}

	// AccountListener
	void
	onMessageWaitingIndicationChanged(const std::shared_ptr<linphone::Account>& account,
	                                  const std::shared_ptr<const linphone::MessageWaitingIndication>& mwi) override;

	MwiCoreStats mStats;
};

} // namespace flexisip::tester