/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "exceptions/bad-configuration.hh"
#include "flexisip/registrar/registar-listeners.hh"
#include "flexisip/utils/sip-uri.hh"
#include "linphone++/enums.hh"
#include "registrar/record.hh"
#include "utils/configuration/transport.hh"
#include "xml/reginfo.hh"

using namespace std;
using namespace linphone;
using namespace reginfo;
using namespace flexisip::Xsd::XmlSchema;

namespace flexisip::RegistrationEvent {

Server::Subscription::Subscription(const std::shared_ptr<linphone::Event>& event) : mEvent(event) {
}

void Server::Subscription::onRecordFound(const shared_ptr<Record>& record) {
	processRecord(record, "");
}

void Server::Subscription::onError(const flexisip::SipStatus&) {
}

void Server::Subscription::onInvalid(const flexisip::SipStatus&) {
}

void Server::Subscription::onContactUpdated(const std::shared_ptr<ExtendedContact>&) {
}

void Server::Subscription::onContactRegistered(const shared_ptr<Record>& record, const string& uidOfFreshlyRegistered) {
	processRecord(record, uidOfFreshlyRegistered);
}

void Server::Subscription::processRecord(const shared_ptr<Record>& record, const string& uidOfFreshlyRegistered) {
	if (!record) {
		LOGI << "Ignoring registration notification: record pointer is empty";
		return;
	}

	const auto& aor = record->getKey().asString();
	Reginfo registrationInfo{0, State::Value::full};
	Registration registration{Uri(mEvent->getTo()->asString().c_str()), aor.c_str(), Registration::StateType::active};
	sofiasip::Home home{};

	for (const auto& ec : record->getExtendedContacts()) {
		auto addr = record->getPubGruu(ec, home.home());
		if (!addr) {
			LOGD << "Skipping contact with no 'GRUU' (contact: " << ec->urlAsString() << ", aor: " << aor << ")";
			continue;
		}

		bool justRegistered = (ec->mKey == uidOfFreshlyRegistered);

		Contact contact{url_as_string(home.home(), addr), Contact::StateType::active,
		                justRegistered ? Contact::EventType::refreshed : Contact::EventType::registered,
		                url_as_string(home.home(), addr)};

		if (ec->mSipContact->m_expires) {
			try {
				contact.setExpires(stoi(ec->mSipContact->m_expires));
			} catch (const exception& exception) {
				LOGI << "Failed to convert 'expires' value from string (" << ec->mSipContact->m_expires << ")";
				return;
			}
		}

		if (ec->mSipContact->m_params) {
			size_t i;

			for (i = 0; ec->mSipContact->m_params[i]; i++) {
				const auto param = string_utils::split(string_view{ec->mSipContact->m_params[i]}, "=");

				auto unknownParam = UnknownParam(string{param.front()});
				if (param.size() == 2) {
					unknownParam.append(string_utils::unquote(string{param.back()}));
				}

				contact.getUnknownParam().push_back(unknownParam);
			}
		}

		contact.setDisplayName(ec->getDeviceName().asString());
		registration.getContact().push_back(contact);
	}

	registration.setState(record->getExtendedContacts().empty() ? Registration::StateType::terminated
	                                                            : Registration::StateType::active);

	registrationInfo.getRegistration().push_back(registration);

	stringstream xmlBody{};
	serializeReginfo(xmlBody, registrationInfo);
	const auto body = xmlBody.str();

	const auto notifyContent = Factory::get()->createContent();
	notifyContent->setBuffer(reinterpret_cast<const uint8_t*>(body.data()), body.length());
	notifyContent->setType("application");
	notifyContent->setSubtype("reginfo+xml");

	mEvent->notify(notifyContent);
}

std::shared_ptr<linphone::Event> Server::Subscription::getEvent() const {
	return mEvent;
}

Server::Application::Application(const std::shared_ptr<RegistrarDb>& registrarDb)
    : mRegistrarDb(registrarDb), mSubscriptions() {
}

void Server::Application::onSubscribeReceived(const shared_ptr<Core>&,
                                              const shared_ptr<linphone::Event>& event,
                                              const string&,
                                              const shared_ptr<const Content>&) {
	LOGD << "Received new Subscription[event=" << event << "]";

	const auto eventHeader = event->getName();
	if (eventHeader != "reg") {
		LOGI << "Rejected: 'Event' header value is not set to 'reg'";
		event->denySubscription(Reason::BadEvent);
		return;
	}

	const auto acceptHeader = event->getCustomHeader("Accept");
	if (acceptHeader != Server::kContentType) {
		LOGI << "Rejected: 'Accept' header value is not set to '" << Server::kContentType << "'";
		event->denySubscription(Reason::NotAcceptable);
		return;
	}

	SipUri toUri{};
	try {
		toUri = SipUri(event->getTo()->asStringUriOnly());
	} catch (const exception& exception) {
		LOGI << "Rejected: invalid URI in 'To' header (" << exception.what() << ")";
		event->denySubscription(Reason::AddressIncomplete);
		return;
	}

	const auto recordKey = Record::Key(toUri, mRegistrarDb->useGlobalDomain());
	const auto fromUri = event->getFromAddress()->asStringUriOnly();

	// Iterator to the record key in the subscriptions map.
	auto recordKeyIt = mSubscriptions.insert({recordKey.asString(), {}}).first;

	auto& subscriptions = recordKeyIt->second;
	const auto subscriptionIt =
	    find_if(subscriptions.begin(), subscriptions.end(), [&fromUri](const auto& subscription) {
		    return subscription->getEvent()->getFromAddress()->asStringUriOnly() == fromUri;
	    });

	// If subscriber already exists, replace the old subscription with the new one.
	if (subscriptionIt != subscriptions.end()) {
		LOGD << "Replacing Subscription[event=" << (*subscriptionIt)->getEvent() << "] from '" << fromUri
		     << "' to record key '" << recordKey.asString() << "'";
		subscriptions.erase(subscriptionIt);
	}
	subscriptions.emplace_back(make_shared<Subscription>(event));
	LOGD << "Added Subscription[event=" << event << "] from '" << fromUri << "' to record key '" << recordKey.asString()
	     << "'";

	LOGD << "Record key '" << recordKey.asString() << "' has " << subscriptions.size() << " subscriptions";

	// Accept the subscription to be able to notify it.
	event->acceptSubscription();

	mRegistrarDb->fetch(toUri, subscriptions.back(), true);
	mRegistrarDb->subscribe(recordKey, subscriptions.back());
}

void Server::Application::onSubscriptionStateChanged(const shared_ptr<linphone::Core>&,
                                                     const shared_ptr<linphone::Event>& event,
                                                     linphone::SubscriptionState state) {
	LOGD << "Subscription[event=" << event << "] state changed to " << static_cast<int>(state);

	switch (state) {
		case linphone::SubscriptionState::Terminated: {
			SipUri toUri{};
			try {
				toUri = SipUri(event->getTo()->asStringUriOnly());
			} catch (const exception& exception) {
				LOGI << "Subscription[event=" << event << "] terminated: invalid URI in 'To' header ("
				     << exception.what() << ")";
				return;
			}

			const auto recordKey = Record::Key(toUri, mRegistrarDb->useGlobalDomain()).toString();
			if (mSubscriptions.find(recordKey) == mSubscriptions.end()) {
				LOGD << "Subscription[event=" << event
				     << "] terminated: nothing to do as there is no subscription to record key '" << recordKey << "'";
				return;
			}

			// Remove subscription for current fromUri.
			auto& subscriptions = mSubscriptions[recordKey];
			const auto fromUri = event->getFromAddress()->asStringUriOnly();
			const auto subscriptionIt =
			    find_if(subscriptions.begin(), subscriptions.end(), [&fromUri](const auto& subscription) {
				    return subscription->getEvent()->getFromAddress()->asStringUriOnly() == fromUri;
			    });

			if (subscriptionIt != subscriptions.end()) {
				subscriptions.erase(subscriptionIt);
				LOGD << "Removed Subscription[event=" << event << "] from '" << fromUri << "' to record key '"
				     << recordKey << "'";
			} else {
				LOGD << "Tried to remove Subscription[event=" << event << "] to '" << recordKey
				     << "' but event pointer was not found in the subscriptions vector";
			}

			// Remove key if there are no more subscriptions to it.
			if (mSubscriptions[recordKey].empty()) {
				mSubscriptions.erase(recordKey);
				LOGI << "Removed record key '" << recordKey
				     << "' from subscriptions map (no more active subscriptions)";
			}
		} break;
		default:
			break;
	}
}

void Server::_init() {
	mCore = Factory::get()->createCore("", "", nullptr);
	mCore->enableDatabase(false);

	const auto* config = mConfigManager->getRoot()->get<GenericStruct>("regevent-server");
	const auto* transportParameter = config->get<ConfigString>("transport");
	const auto transports = Factory::get()->createTransports();
	configuration_utils::configureTransport(transports, transportParameter, {"tcp"});

	mCore->setTransports(transports);
	mCore->addListener(make_shared<Application>(mRegistrarDb));
	mCore->start();
}

void Server::_run() {
	mCore->iterate();
}

unique_ptr<AsyncCleanup> Server::_stop() {
	mCore = nullptr;
	return nullptr;
}

namespace {
// Statically define default configuration items.
auto& defineConfig = ConfigManager::defaultInit().emplace_back([](GenericStruct& root) {
	ConfigItemDescriptor items[] = {
	    {
	        String,
	        "transport",
	        "SIP URI on which the server is listening on.\n"
	        "WARNING: only 'TCP' transport is supported.",
	        "sip:127.0.0.1:6065;transport=tcp",
	    },
	    config_item_end,
	};

	auto uS =
	    make_unique<GenericStruct>("regevent-server",
	                               "Flexisip RegEvent server parameters.\n"
	                               "This server is in charge of responding to SIP SUBSCRIBE requests for the 'reg' "
	                               "event as defined by RFC3680 (https://tools.ietf.org/html/rfc3680).\n"
	                               "It relies on the registrar database setup in the 'module::Registrar' section to "
	                               "generate outgoing NOTIFY requests",
	                               0);
	auto* s = root.addChild(std::move(uS));
	s->addChildrenValues(items);
});

} // namespace
} // namespace flexisip::RegistrationEvent