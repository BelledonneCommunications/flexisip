/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <exception>
#include <iostream>
#include <sstream>

#include <linphone++/linphone.hh>
#include <stdexcept>

#include "flexisip/logmanager.hh"

#include "utils/string-utils.hh"
#include "xml/reginfo.hh"

#include "client.hh"

using namespace std;
using namespace linphone;
using namespace reginfo;

namespace flexisip {

namespace RegistrationEvent {

Client::Client(const shared_ptr<ClientFactory>& factory, const shared_ptr<const Address>& to)
    : mFactory(factory), mTo(to->clone()) {
	mFactory->registerClient(*this);
}

void Client::subscribe() {
	if (mSubscribeEvent) {
		LOGE("Already subscribed.");
		return;
	}
	mSubscribeEvent = mFactory->getCore()->createSubscribe(mTo, "reg", 600);
	mSubscribeEvent->addCustomHeader("Accept", "application/reginfo+xml");
	mSubscribeEvent->setData(eventKey, *this);
	mSubscribeEvent->sendSubscribe(nullptr);
}

void Client::unsubscribe() {
	if (!mSubscribeEvent) {
		LOGE("No subscribe.");
		return;
	}
	mSubscribeEvent->unsetData(eventKey);
	mSubscribeEvent->terminate();
	mSubscribeEvent = nullptr;
}

Client::~Client() {
	mFactory->unregisterClient(*this);
	/* It is not possible to call shared_from_this() from here because we are in the destructor,
	 so not possible to remove us as a core listener. Too late.*/
	if (mSubscribeEvent) {
		mSubscribeEvent->unsetData(eventKey);
		mSubscribeEvent->terminate();
	}
}

void Client::setListener(ClientListener* listener) {
	mListener = listener;
}

void Client::onNotifyReceived(const std::shared_ptr<const linphone::Content>& body) {
	if (!body) throw runtime_error("Empty notify Content.");

	istringstream data(body->getUtf8Text());

	unique_ptr<Reginfo> ri(parseReginfo(data, Xsd::XmlSchema::Flags::dont_validate));

	for (const auto& registration : ri->getRegistration()) {
		if (registration.getState() == Registration::StateType::terminated) {
			if (mListener) mListener->onNotifyReceived({}); // Notifying that 0 devices are registered.
			continue;
		}

		list<shared_ptr<ParticipantDeviceIdentity>> participantDevices;
		size_t refreshed = 0;
		for (const auto& contact : registration.getContact()) {
			auto partDeviceAddr = Factory::get()->createAddress(contact.getUri());
			Contact::UnknownParamSequence ups = contact.getUnknownParam();
			string displayName = contact.getDisplayName() ? contact.getDisplayName()->c_str() : string("");

			for (const auto& param : ups) {
				if (param.getName() != "+org.linphone.specs") continue;
				shared_ptr<ParticipantDeviceIdentity> identity =
				    Factory::get()->createParticipantDeviceIdentity(partDeviceAddr, displayName);
				identity->setCapabilityDescriptor(StringUtils::unquote(param));

				if (contact.getEvent() == reginfo::Event::refreshed) {
					if (mListener) mListener->onRefreshed(identity);
					refreshed++;
				}
				participantDevices.push_back(identity);
				break;
			}
		}

		if (refreshed < participantDevices.size()) {
			if (mListener) mListener->onNotifyReceived(participantDevices);
		} /* else: Everything is refreshed, notifying a reception would be redundant */
	}
}

void Client::onSubscriptionStateChanged(linphone::SubscriptionState state) {
	switch (state) {
		case SubscriptionState::None:
		case SubscriptionState::OutgoingProgress:
		case SubscriptionState::IncomingReceived:
		case SubscriptionState::Pending:
		case SubscriptionState::Active:
		case SubscriptionState::Expiring:
			break;
		case SubscriptionState::Terminated:
		case SubscriptionState::Error:
			mSubscribeEvent->unsetData(eventKey);
			mSubscribeEvent->terminate();
			mSubscribeEvent = nullptr;
			/* TODO: retry later*/
			break;
	}
}

void ClientFactory::onSubscriptionStateChanged([[maybe_unused]] const std::shared_ptr<linphone::Core>& core,
                                               const std::shared_ptr<linphone::Event>& linphoneEvent,
                                               linphone::SubscriptionState state) {
	try {
		Client& client = linphoneEvent->getData<Client>(Client::eventKey);
		client.onSubscriptionStateChanged(state);
	} catch (const std::out_of_range&) {
		LOGW("ClientFactory::onSubscriptionStateChanged: Client disconnected");
	} catch (const std::exception& exc) {
		SLOGE << "ClientFactory::onSubscriptionStateChanged: " << exc.what();
	}
}

void ClientFactory::onNotifyReceived([[maybe_unused]] const shared_ptr<Core>& lc,
                                     const shared_ptr<linphone::Event>& lev,
                                     [[maybe_unused]] const string& notifiedEvent,
                                     const shared_ptr<const Content>& body) {
	try {
		Client& client = lev->getData<Client>(Client::eventKey);
		client.onNotifyReceived(body);
	} catch (const std::out_of_range&) {
		LOGW("ClientFactory::onSubscriptionStateChanged: Client disconnected");
	} catch (const std::exception& exc) {
		SLOGE << "ClientFactory::onSubscriptionStateChanged: " << exc.what();
	}
}

void ClientFactory::registerClient([[maybe_unused]] Client& client) {
	if (mUseCount == 0) {
		mCore->addListener(shared_from_this());
	}
	mUseCount++;
}
void ClientFactory::unregisterClient([[maybe_unused]] Client& client) {
	mUseCount--;
	if (mUseCount == 0) {
		mCore->removeListener(shared_from_this());
	}
}

ClientFactory::ClientFactory(const std::shared_ptr<linphone::Core>& core) : mCore(core) {
}

std::shared_ptr<Client> ClientFactory::create(const std::shared_ptr<const linphone::Address>& to) {
	return shared_ptr<Client>(new Client(shared_from_this(), to));
}

} // namespace RegistrationEvent

} // namespace flexisip
