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

#include "client.hh"

#include <exception>
#include <sstream>
#include <stdexcept>

#include "flexisip/logmanager.hh"
#include "linphone++/linphone.hh"
#include "utils/string-utils.hh"
#include "xml/reginfo.hh"

using namespace std;
using namespace linphone;
using namespace reginfo;

namespace flexisip::RegistrationEvent {

Client::Client(const shared_ptr<ClientFactory>& factory, const shared_ptr<const Address>& to)
    : mSubscribeEvent(), mFactory(factory), mTo(to->clone()), mListener(nullptr),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "Client")) {
	mFactory->registerClient(*this);
}

void Client::subscribe() {
	if (mSubscribeEvent) {
		LOGE << "Already subscribed";
		return;
	}
	mSubscribeEvent = mFactory->getCore()->createSubscribe(mTo, "reg", mFactory->getSubscriptionRefreshDelay().count());
	mSubscribeEvent->addCustomHeader("Accept", "application/reginfo+xml");
	mSubscribeEvent->setData(kEventKey, *this);
	mSubscribeEvent->sendSubscribe(nullptr);
}

void Client::unsubscribe() {
	if (!mSubscribeEvent) {
		LOGE << "No subscription";
		return;
	}
	mSubscribeEvent->unsetData(kEventKey);
	mSubscribeEvent->terminate();
	mSubscribeEvent = nullptr;
}

Client::~Client() {
	mFactory->unregisterClient(*this);
	// It is not possible to call shared_from_this() from here because we are in the destructor,
	// so not possible to remove us as a core listener. It is too late.
	if (mSubscribeEvent) {
		mSubscribeEvent->unsetData(kEventKey);
		mSubscribeEvent->terminate();
	}
}

void Client::setListener(ClientListener* listener) {
	mListener = listener;
}

void Client::onNotifyReceived(const shared_ptr<const linphone::Content>& body) {
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

				identity->setCapabilityDescriptor(list<string>{StringUtils::unquote(param)});

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
		} // else: Everything is refreshed, notifying a reception would be redundant.
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
			mSubscribeEvent->unsetData(kEventKey);
			mSubscribeEvent->terminate();
			mSubscribeEvent = nullptr;
			/* TODO: retry later*/
			break;
	}
}

void ClientFactory::onSubscriptionStateChanged(const shared_ptr<linphone::Core>&,
                                               const shared_ptr<linphone::Event>& linphoneEvent,
                                               linphone::SubscriptionState state) {
	try {
		auto& client = linphoneEvent->getData<Client>(Client::kEventKey);
		client.onSubscriptionStateChanged(state);
	} catch (const out_of_range&) {
		LOGI << "Client disconnected";
	} catch (const exception& exception) {
		LOGD << "Caught an unexpected exception on subscription state change:" << exception.what();
	}
}

void ClientFactory::onNotifyReceived(const shared_ptr<Core>&,
                                     const shared_ptr<linphone::Event>& lev,
                                     const string&,
                                     const shared_ptr<const Content>& body) {
	try {
		auto& client = lev->getData<Client>(Client::kEventKey);
		client.onNotifyReceived(body);
	} catch (const out_of_range&) {
		LOGI << "Client disconnected";
	} catch (const exception& exception) {
		LOGD << "Caught an unexpected exception on NOTIFY request receipt:" << exception.what();
	}
}

void ClientFactory::registerClient(Client&) {
	if (mUseCount == 0) {
		mCore->addListener(shared_from_this());
	}
	mUseCount++;
}
void ClientFactory::unregisterClient(Client&) {
	mUseCount--;
	if (mUseCount == 0) {
		mCore->removeListener(shared_from_this());
	}
}

ClientFactory::ClientFactory(const shared_ptr<linphone::Core>& core, const chrono::seconds& subscriptionRefreshDelay)
    : mCore(core), mSubscriptionRefreshDelay(subscriptionRefreshDelay), mUseCount(0) {
}

shared_ptr<Client> ClientFactory::create(const shared_ptr<const linphone::Address>& to) {
	return shared_ptr<Client>(new Client{shared_from_this(), to});
}

chrono::seconds ClientFactory::getSubscriptionRefreshDelay() const {
	return mSubscriptionRefreshDelay;
}

} // namespace flexisip::RegistrationEvent