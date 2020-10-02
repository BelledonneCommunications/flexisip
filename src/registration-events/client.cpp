/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <iostream>
#include <sstream>

#include <linphone++/linphone.hh>

#include "conference/conference-server.hh"
#include "utils.hh"
#include "xml/reginfo.hh"

#include "client.hh"

using namespace std;
using namespace linphone;
using namespace reginfo;

namespace flexisip {

namespace RegistrationEvent {

Client::Client(
    const ConferenceServer & server,
    const shared_ptr<ChatRoom> & chatRoom,
    const shared_ptr<const Address> to) : mServer(server), mChatRoom(chatRoom), mTo(to) {}

void Client::subscribe() {
    mSubscribeEvent = mChatRoom->getCore()->createSubscribe(mTo, "reg", 600);
    mSubscribeEvent->addCustomHeader("Accept", "application/reginfo+xml");

    shared_ptr<Content> subsContent = Factory::get()->createContent();
    subsContent->setType("application");
    subsContent->setSubtype("xml");
    string notiFybody("Subscribe");
    subsContent->setBuffer((uint8_t *)notiFybody.data(), notiFybody.length());

    mSubscribeEvent->sendSubscribe(subsContent);
    mChatRoom->getCore()->addListener(shared_from_this());
}

Client::~Client () {
    mChatRoom->getCore()->removeListener(shared_from_this());
}

void Client::onNotifyReceived(
    const shared_ptr<Core> & lc,
    const shared_ptr<linphone::Event> & lev,
    const string & notifiedEvent,
    const shared_ptr<const Content> & body
) {
    notifyReceived = true;
    istringstream data(body->getStringBuffer());

    unique_ptr<Reginfo> ri(parseReginfo(data, Xsd::XmlSchema::Flags::dont_validate));

    for (const auto &registration : ri->getRegistration()) {
        list<shared_ptr<ParticipantDeviceIdentity>> participantDevices;

        for (const auto &contact : registration.getContact()) {
            auto partDeviceAddr = Factory::get()->createAddress(contact.getUri());

            Contact::UnknownParamSequence ups = contact.getUnknownParam();

            for (const auto &param : ups) {
                if (Utils::isContactCompatible(mServer, mChatRoom, param)) {
                    string displayName = contact.getDisplayName()
                        ? contact.getDisplayName()->c_str()
                        : string("");

                    shared_ptr<ParticipantDeviceIdentity> identity = Factory::get()->createParticipantDeviceIdentity(
                        partDeviceAddr,
                        displayName
                    );

                    participantDevices.push_back(identity);
                    break;
                }
            }
        }

        auto partAddr = Factory::get()->createAddress(registration.getAor());

        if (registration.getState() == Registration::StateType::terminated) {
            auto participant = this->mChatRoom->findParticipant(partAddr);
            if (participant) this->mChatRoom->removeParticipant(participant);
        } else {
            this->mChatRoom->setParticipantDevices(partAddr, participantDevices);
        }
    }

}

} // namespace RegistrationEvent

} // namespace flexisip
