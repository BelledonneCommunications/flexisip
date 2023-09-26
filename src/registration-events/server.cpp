/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "server.hh"

#include <memory>

#include "linphone++/enums.hh"
#include "xml/reginfo.hh"

#include "flexisip/registrar/registar-listeners.hh"
#include <flexisip/utils/sip-uri.hh>

#include "registrar/record.hh"
#include "registrar/registrar-db.hh"

using namespace std;
using namespace linphone;
using namespace reginfo;
using namespace flexisip::Xsd::XmlSchema;

namespace flexisip {

namespace RegistrationEvent {

static constexpr const char* CONTENT_TYPE = "application/reginfo+xml";

Server::Init Server::sStaticInit; // The Init object is instanciated to load the config

void Server::Subscriptions::onSubscribeReceived(const shared_ptr<Core>& core,
                                                const shared_ptr<linphone::Event>& lev,
                                                const string&,
                                                const shared_ptr<const Content>&) {
	string eventHeader = lev->getName();
	if (eventHeader != "reg") {
		lev->denySubscription(Reason::BadEvent);
		return;
	}

	string acceptHeader = lev->getCustomHeader("Accept");
	if (acceptHeader != RegistrationEvent::CONTENT_TYPE) {
		lev->denySubscription(Reason::NotAcceptable);
		return;
	}

	SipUri url;
	try {
		url = SipUri(lev->getTo()->asStringUriOnly());
	} catch (const sofiasip::InvalidUrlError& e) {
		SLOGE << "Regevent server: new subscription: invalid URI in 'To' header: " << e.getUrl();
		lev->denySubscription(Reason::AddressIncomplete);
		return;
	}

	const auto result = mEvents.emplace(Record::Key(url), lev);
	if (!result.second) {
		SLOGE << "Regevent server: There is already a subscription for: " << result.first->first;
		lev->denySubscription(Reason::Busy);
		return;
	}

	// Accept the sub to be able to notify it
	lev->acceptSubscription();
	// We need the core to send the NOTIFY (and it holds `this`). So we pass it as the callback to make sure it lives
	// long enough
	RegistrarDb::get()->fetch(url, {core, this}, true);
	// Subscribe takes a weak_ptr. Passing it the event itself lets us unsubscribe automatically by deleting the event.
	RegistrarDb::get()->subscribe(Record::Key(url), std::shared_ptr<ContactRegisteredListener>{lev, this});
}

void Server::Subscriptions::onSubscriptionStateChanged(const std::shared_ptr<linphone::Core>&,
                                                       const std::shared_ptr<linphone::Event>& lev,
                                                       linphone::SubscriptionState state) {
	switch (state) {
		case linphone::SubscriptionState::Terminated: {
			SipUri url;
			try {
				url = SipUri(lev->getTo()->asStringUriOnly());
			} catch (const sofiasip::InvalidUrlError& e) {
				SLOGE << "Regevent server: subscription terminated: invalid URI in 'To' header: " << e.getUrl();
				return;
			}

			mEvents.erase(Record::Key(url));
		} break;
		default:
			break;
	}
}

void Server::Subscriptions::onRecordFound(const shared_ptr<Record>& r) {
	processRecord(r, "");
}

void Server::Subscriptions::onContactRegistered(const shared_ptr<Record>& r, const string& uidOfFreshlyRegistered) {
	processRecord(r, uidOfFreshlyRegistered);
}

void Server::Subscriptions::processRecord(const shared_ptr<Record>& r, const std::string& uidOfFreshlyRegistered) {
	if (!r) {
		SLOGW << "RegistrationEvent::Server - Ignoring registration notification with null record.";
		return;
	}

	const string& aor = r->getKey();
	const auto maybeEvent = mEvents.find(aor);
	if (maybeEvent == mEvents.end()) {
		SLOGW << "RegistrationEvent::Server - Ignoring registration of a contact no one is subscribed to. "
		         "(aor: "
		      << aor << ")";
		return;
	}
	auto& event = *maybeEvent->second;

	Reginfo ri{0, State::Value::full};
	Registration re{Uri(event.getTo()->asString().c_str()), aor.c_str(), Registration::StateType::active};
	sofiasip::Home home{};

	for (const auto& ec : r->getExtendedContacts()) {
		auto addr = r->getPubGruu(ec, home.home());
		if (!addr) {
			SLOGE << "RegistrationEvent::Server - Contact has no GRUU, skipping. (contact: " << ec->urlAsString()
			      << ", aor: " << aor << ")";
			continue;
		}
		bool justRegistered = (ec->mKey == uidOfFreshlyRegistered);

		Contact contact(url_as_string(home.home(), addr), Contact::StateType::active,
		                justRegistered ? Contact::EventType::refreshed : Contact::EventType::registered,
		                url_as_string(home.home(), addr));

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
	}

	re.setState(r->getExtendedContacts().size() == 0 ? Registration::StateType::terminated
	                                                 : Registration::StateType::active);

	ri.getRegistration().push_back(re);

	stringstream xmlBody;
	serializeReginfo(xmlBody, ri);
	string body = xmlBody.str();

	auto notifyContent = Factory::get()->createContent();
	notifyContent->setBuffer((uint8_t*)body.data(), body.length());
	notifyContent->setType("application");
	notifyContent->setSubtype("reginfo+xml");

	event.notify(notifyContent);
};

void Server::_init() {
	mCore = Factory::get()->createCore("", "", nullptr);
	auto config = GenericManager::get()->getRoot()->get<GenericStruct>("regevent-server");

	mCore->getConfig()->setString("storage", "uri", "null");

	shared_ptr<Transports> regEventTransport = Factory::get()->createTransports();
	string mTransport = config->get<ConfigString>("transport")->read();
	if (mTransport.length() > 0) {
		sofiasip::Home mHome;
		url_t* urlTransport = url_make(mHome.home(), mTransport.c_str());
		if (urlTransport == nullptr || mTransport.at(0) == '<') {
			LOGF("ConferenceServer: Your configured conference transport(\"%s\") is not an URI.\n"
			     "If you have \"<>\" in your transport, remove them.",
			     mTransport.c_str());
		}
		regEventTransport->setTcpPort(stoi(urlTransport->url_port));
	}

	mCore->setTransports(regEventTransport);
	mCore->addListener(make_shared<Subscriptions>());
	mCore->start();
}

void Server::_run() {
	mCore->iterate();
}

void Server::_stop() {
	mCore = nullptr;
}

Server::Init::Init() {
	ConfigItemDescriptor items[] = {{String, "transport", "SIP uri on which the RegEvent server is listening on.",
	                                 "sip:127.0.0.1:6065;transport=tcp"},
	                                config_item_end};

	auto uS = make_unique<GenericStruct>(
	    "regevent-server",
	    "Flexisip RegEvent server parameters."
	    "The regevent server is in charge of responding to SIP SUBSCRIBEs for the 'reg' event as defined by RFC3680"
	    " - A Session Initiation Protocol (SIP) Event Package for Registrations - https://tools.ietf.org/html/rfc3680 ."
	    "To generate the outgoing NOTIFY, it will rely upon the registrar database, as setup in module::Registrar "
	    "section.",
	    0);
	auto s = GenericManager::get()->getRoot()->addChild(std::move(uS));
	s->addChildrenValues(items);
}

} // namespace RegistrationEvent

} // namespace flexisip
