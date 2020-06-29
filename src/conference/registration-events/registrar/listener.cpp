#include "listener.hh"
#include "resource-lists.hh"
#include "reginfo.hh"

using namespace std;
using namespace linphone;
using namespace reginfo;
using namespace Xsd::ResourceLists;
using namespace Xsd::XmlSchema;

namespace RegistrationEvent::Registrar {

Listener::Listener(const shared_ptr<linphone::Event> &lev): event(lev) {}

void Listener::onRecordFound(const shared_ptr<Record> &r) {
    this->processRecord(r);
}

void Listener::onContactRegistered(const shared_ptr<Record> &r, const string &uid) {
    this->processRecord(r);
}

void Listener::processRecord(const shared_ptr<Record> &r) {
    list<shared_ptr<ParticipantDeviceIdentity>> compatibleParticipantDevices;

    Reginfo ri = Reginfo(0, State::Value::full);
    Registration re = Registration(
        Uri(this->event->getFrom()->asString().c_str()),
        "123",
        Registration::StateType::active
    );

    if (r) {
        for (const shared_ptr<ExtendedContact> &ec : r->getExtendedContacts()) {
            Contact contact = Contact(
                ec->getUniqueId(),
                Contact::StateType::active,
                Contact::EventType::registered, ec->getUniqueId()
            );

            // unknown-params
            if (ec->mSipContact->m_params) {
                size_t i;

                for (i = 0; ec->mSipContact->m_params[i]; i++) {
                    auto unknownParam = UnknownParam(ec->mSipContact->m_params[i]);
                    if (strcmp(msg_params_find(ec->mSipContact->m_params, ec->mSipContact->m_params[i]), "") != 0) {
                        unknownParam.setName(msg_params_find(ec->mSipContact->m_params, ec->mSipContact->m_params[i]));
                    }

                    contact.getUnknownParam().push_back(unknownParam);
                }
            }

            contact.setDisplayName(this->getDeviceName(ec));
            re.getContact().push_back(contact);
        }
    }

    ri.getRegistration().push_back(re);

    stringstream xmlBody;
    serializeReginfo(xmlBody, ri);
    string body = xmlBody.str();

    auto notifyContent = Factory::get()->createContent();
    notifyContent->setBuffer((uint8_t *)body.data(), body.length());
    notifyContent->setType("application");
    notifyContent->setSubtype("reginfo+xml");

    this->event->notify(notifyContent);
};

string Listener::getDeviceName(const shared_ptr<ExtendedContact> &ec) {
    const string &userAgent = ec->getUserAgent();
    size_t begin = userAgent.find("(");
    string deviceName;

    if (begin != string::npos) {
        size_t end = userAgent.find(")", begin);
        size_t openingParenthesis = userAgent.find("(", begin + 1);

        while (openingParenthesis != string::npos && openingParenthesis < end) {
            openingParenthesis = userAgent.find("(", openingParenthesis + 1);
            end = userAgent.find(")", end + 1);
        }

        if (end != string::npos){
            deviceName = userAgent.substr(begin + 1, end - (begin + 1));
        }
    }

    return deviceName;
}

}
