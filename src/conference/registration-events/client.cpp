#include "client.hh"
#include "reginfo.hh"

#include <linphone++/linphone.hh>

#include <iostream>
#include <sstream>

using namespace std;
using namespace linphone;
using namespace reginfo;

namespace RegistrationEvent {

Client::Client(
    const shared_ptr<Core> & lc,
    const shared_ptr<Address> to,
    const shared_ptr<ChatRoom> &chatRoom) : core(lc), to(to), chatRoom(chatRoom) {}

void Client::subscribe() {
    subscribeEvent = core->createSubscribe(to, "reg", 600);
    subscribeEvent->addCustomHeader("Accept", "application/reginfo+xml");
    subscribeEvent->addCustomHeader("Event", "reg");

    shared_ptr<Content> subsContent = Factory::get()->createContent();
    subsContent->setType("application");
    subsContent->setSubtype("xml");
    string notiFybody("Subscribe");
    subsContent->setBuffer((uint8_t *)notiFybody.data(), notiFybody.length());

    subscribeEvent->sendSubscribe(subsContent);
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
            shared_ptr<ParticipantDeviceIdentity> identity = Factory::get()->createParticipantDeviceIdentity(
                Factory::get()->createAddress(contact.getUri().text_content()), contact.getDisplayName()->text_content());
            participantDevices.push_back(identity);
        }
    }

    this->chatRoom->setParticipantDevices(to, participantDevices);
}

} // namespace RegistrationEvent
