/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "mwi-listener.hh"
#include "flexisip/logmanager.hh"

namespace flexisip::tester {

void MwiListener::onSubscribeReceived(const std::shared_ptr<linphone::Core>& core,
                                      const std::shared_ptr<linphone::Event>& linphoneEvent,
                                      const std::string& subscribeEvent,
                                      [[maybe_unused]] const std::shared_ptr<const linphone::Content>& body) {
	mStats.nbSubscribeReceived++;
	linphoneEvent->acceptSubscription();

	if (subscribeEvent == "message-summary") {
		auto mwi_stream = std::ostringstream();
		mwi_stream << "Messages-Waiting: yes\r\n"
		           << "Message-Account: " << linphoneEvent->getFromAddress()->asStringUriOnly() << "\r\n"
		           << "Voice-Message: 4/8 (1/2)\r\n";
		std::string mwi = mwi_stream.str();

		auto content = core->createContent();
		content->setType("application");
		content->setSubtype("simple-message-summary");
		content->setBuffer(reinterpret_cast<const uint8_t*>(mwi.c_str()), mwi.size());
		linphoneEvent->notify(content);
	}
}

void MwiListener::onSubscriptionStateChanged(const std::shared_ptr<linphone::Core>&,
                                             const std::shared_ptr<linphone::Event>&,
                                             linphone::SubscriptionState state) {
	if (state == linphone::SubscriptionState::Active) {
		mStats.nbSubscribeActive++;
	} else if (state == linphone::SubscriptionState::Terminated) {
		mStats.nbSubscribeTerminated++;
	}
}

void MwiListener::onMessageWaitingIndicationChanged(
    const std::shared_ptr<linphone::Account>&, const std::shared_ptr<const linphone::MessageWaitingIndication>& mwi) {
	if (mwi->hasMessageWaiting()) {
		mStats.nbMwiReceived++;
	}
	auto summary = mwi->getSummary(linphone::MessageWaitingIndication::ContextClass::Voice);
	if (summary) {
		mStats.nbNewMWIVoice = summary->getNbNew();
		mStats.nbOldMWIVoice = summary->getNbOld();
		mStats.nbNewUrgentMWIVoice = summary->getNbNewUrgent();
		mStats.nbOldUrgentMWIVoice = summary->getNbOldUrgent();
	}
}

} // namespace flexisip::tester