#include "client.hh"
#include "reginfo.hh"
#include "utils.hh"
#include "../conference-server.hh"

#include <linphone++/linphone.hh>

#include <iostream>
#include <sstream>

using namespace std;
using namespace linphone;
using namespace reginfo;
using namespace flexisip;

namespace RegistrationEvent {

Client::Client(
    const ConferenceServer & server,
    const shared_ptr<ChatRoom> & chatRoom,
    const shared_ptr<const Address> to) : mServer(server), mChatRoom(chatRoom), mTo(to) {}

void Client::subscribe() {
    mSubscribeEvent = mChatRoom->getCore()->createSubscribe(mTo, "reg", 600);
    mSubscribeEvent->addCustomHeader("Accept", "application/reginfo+xml");
    mSubscribeEvent->addCustomHeader("Event", "reg");

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

    list<shared_ptr<ParticipantDeviceIdentity>> participantDevices;
    unique_ptr<Reginfo> ri(parseReginfo(data, Xsd::XmlSchema::Flags::dont_validate));

    for (const auto &registration : ri->getRegistration()) {
        for (const auto &contact : registration.getContact()) {

            string displayName = contact.getDisplayName()
                ? contact.getDisplayName()->c_str()
                : string("");

            shared_ptr<ParticipantDeviceIdentity> identity = Factory::get()->createParticipantDeviceIdentity(
                Factory::get()->createAddress(contact.getUri()),
                displayName
            );

            Contact::UnknownParamSequence ups = contact.getUnknownParam();

            for (const auto &param : ups) {
                if (Utils::isContactCompatible(mServer, mChatRoom, param)) {
                    participantDevices.push_back(identity);
                    break;
                }
            }
        }
    }

    this->mChatRoom->setParticipantDevices(mTo, participantDevices);
}

} // namespace RegistrationEvent
