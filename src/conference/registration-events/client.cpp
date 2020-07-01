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
    const shared_ptr<const Address> to) : server(server), chatRoom(chatRoom), to(to) {}

void Client::subscribe() {
    subscribeEvent = chatRoom->getCore()->createSubscribe(to, "reg", 600);
    subscribeEvent->addCustomHeader("Accept", "application/reginfo+xml");
    subscribeEvent->addCustomHeader("Event", "reg");

    shared_ptr<Content> subsContent = Factory::get()->createContent();
    subsContent->setType("application");
    subsContent->setSubtype("xml");
    string notiFybody("Subscribe");
    subsContent->setBuffer((uint8_t *)notiFybody.data(), notiFybody.length());

    subscribeEvent->sendSubscribe(subsContent);
    chatRoom->getCore()->addListener(shared_from_this());
}

Client::~Client () {
    chatRoom->getCore()->removeListener(shared_from_this());
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
                Factory::get()->createAddress(contact.getUri().text_content()),
                contact.getDisplayName()->text_content()
            );

            Contact::UnknownParamSequence ups = contact.getUnknownParam();


            //bool groupChat = false;
            //bool lime = false;

            for (const auto &param : ups) {
                if (Utils::isContactCompatible(server, chatRoom, param)) {
                    cout << "DEVICE " << contact.getUri().text_content() << endl;
                    participantDevices.push_back(identity);
                    break;
                }
                //if (string(param).find("groupchat")) groupChat = true;
                //if (param == "lime") lime = true;
            }

            //if (groupChat /*&& lime*/) {
            //}
        }
    }

    this->chatRoom->setParticipantDevices(to, participantDevices);
}

} // namespace RegistrationEvent
