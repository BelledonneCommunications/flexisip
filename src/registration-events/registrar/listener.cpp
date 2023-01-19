/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2023  Belledonne Communications SARL, All rights reserved.

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

#include "utils/string-utils.hh"
#include "xml/reginfo.hh"
#include "xml/resource-lists.hh"

#include "listener.hh"

using namespace std;
using namespace linphone;
using namespace reginfo;
using namespace flexisip::Xsd::ResourceLists;
using namespace flexisip::Xsd::XmlSchema;

namespace flexisip {

namespace RegistrationEvent {
namespace Registrar {

Listener::Listener(const shared_ptr<linphone::Event> &lev): mEvent(lev) {}

void Listener::onRecordFound(const shared_ptr<Record> &r) {
	processRecord(r, "");
}

void Listener::onContactRegistered(const shared_ptr<Record> &r, const string &uid) {
	processRecord(r, uid);
}

void Listener::processRecord(const shared_ptr<Record> &r, const string &uidOfFreshlyRegistered) {
	Reginfo ri(0, State::Value::full);

	if (r) {
		Registration re = Registration(
			Uri(mEvent->getTo()->asString().c_str()),
			r->getKey().c_str(),
			Registration::StateType::active
		);
		sofiasip::Home home;

		for (const shared_ptr<ExtendedContact> &ec : r->getExtendedContacts()) {
			auto addr = r->getPubGruu(ec, home.home());
			bool justRegistered = (ec->getUniqueId() == uidOfFreshlyRegistered);

			Contact contact(url_as_string(home.home(), addr), Contact::StateType::active,
				justRegistered ?  Contact::EventType::refreshed : Contact::EventType::registered, url_as_string(home.home(), addr));

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

			contact.setDisplayName(ec->getDeviceName().asString());
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

	mEvent->notify(notifyContent);
};

}
}

}
