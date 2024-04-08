/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
