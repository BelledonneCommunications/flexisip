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