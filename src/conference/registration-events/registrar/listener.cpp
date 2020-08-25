#include "listener.hh"
#include "resource-lists.hh"
#include "reginfo.hh"
#include "../utils.hh"
#include "utils/string-utils.hh"

using namespace std;
using namespace linphone;
using namespace reginfo;
using namespace Xsd::ResourceLists;
using namespace Xsd::XmlSchema;

namespace RegistrationEvent {
    namespace Registrar {

Listener::Listener(const shared_ptr<linphone::Event> &lev): event(lev) {}

void Listener::onRecordFound(const shared_ptr<Record> &r) {
    this->processRecord(r);
}

void Listener::onContactRegistered(const shared_ptr<Record> &r, const string &uid) {
    this->processRecord(r);
}

void Listener::processRecord(const shared_ptr<Record> &r) {
    Reginfo ri = Reginfo(0, State::Value::full);

    if (r) {
        Registration re = Registration(
            Uri(this->event->getTo()->asString().c_str()),
            r->getKey().c_str(),
            Registration::StateType::active
        );
        sofiasip::Home home;

        for (const shared_ptr<ExtendedContact> &ec : r->getExtendedContacts()) {
            auto addr = r->getPubGruu(ec, home.home());

            Contact contact = Contact(
                url_as_string(home.home(), addr),
                Contact::StateType::active,
                Contact::EventType::registered,
                url_as_string(home.home(), addr)
            );

            // expires
            if (ec->mSipContact->m_expires) {
                contact.setExpires(atoi(ec->mSipContact->m_expires));
            }

            // unknown-params
            if (ec->mSipContact->m_params) {
                size_t i;

                for (i = 0; ec->mSipContact->m_params[i]; i++) {
                    vector<string> param = StringUtils::split(ec->mSipContact->m_params[i], "=");

                    auto unknownParam = UnknownParam(param.front());
                    if (param.size() == 2) {
                        unknownParam.append(StringUtils::unquote(param.back()));
                    }

                    contact.getUnknownParam().push_back(unknownParam);
                }
            }

            contact.setDisplayName(RegistrationEvent::Utils::getDeviceName(ec));
            re.getContact().push_back(contact);

            // If there is some contacts, we set the sate to active
            re.setState(Registration::StateType::active);
        }

        if (r->getExtendedContacts().size() == 0) {
            re.setState(Registration::StateType::terminated);
        }

        ri.getRegistration().push_back(re);
    }

    stringstream xmlBody;
    serializeReginfo(xmlBody, ri);
    string body = xmlBody.str();

    auto notifyContent = Factory::get()->createContent();
    notifyContent->setBuffer((uint8_t *)body.data(), body.length());
    notifyContent->setType("application");
    notifyContent->setSubtype("reginfo+xml");

    this->event->notify(notifyContent);
};

    }
}
