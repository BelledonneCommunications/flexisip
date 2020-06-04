#include "server-registrar-listener.hh"
#include "resource-lists.hh"
#include "reginfo.hh"

using namespace std;
using namespace linphone;
using namespace reginfo;
using namespace Xsd::ResourceLists;
using namespace Xsd::XmlSchema;

ServerRegistrarListener::ServerRegistrarListener(const shared_ptr<linphone::Event> &lev): event(lev) {}

void ServerRegistrarListener::onRecordFound(const shared_ptr<Record> &r) {
    this->processRecord(r);
}

void ServerRegistrarListener::onContactRegistered(const shared_ptr<Record> &r, const string &uid) {
    this->processRecord(r);
}

void ServerRegistrarListener::processRecord(const shared_ptr<Record> &r) {
    list<shared_ptr<ParticipantDeviceIdentity>> compatibleParticipantDevices;

    Reginfo ri = Reginfo(0, State::Value::full);
    Registration re = Registration(
        Uri(this->event->getFrom()->asString().c_str()),
        "123",
        Registration::StateType::active
    );
    ri.getRegistration().push_back(re);

    for (const shared_ptr<ExtendedContact> &ec : r->getExtendedContacts()) {
        // TODO complete
        Contact contact = Contact(ec->getUniqueId(), Contact::StateType::active, Contact::EventType::registered, ec->getUniqueId());
        re.getContact().push_back(contact);
    }

    stringstream xmlBody;
    serializeReginfo(xmlBody, ri);
    string body = xmlBody.str();

    auto notifyContent = Factory::get()->createContent();
    notifyContent->setBuffer((uint8_t *)body.data(), body.length());
    notifyContent->setType("application");
    notifyContent->setSubtype("xml");

    this->event->addCustomHeader("Accept", "application/reginfo+xml");
    this->event->notify(notifyContent);
};