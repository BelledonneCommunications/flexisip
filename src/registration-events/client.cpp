/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2018 Belledonne Communications SARL.

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

#include "client.hh"
#include "reginfo.hh"
#include "utils.hh"

#include <linphone++/linphone.hh>

#include <iostream>
#include <sstream>

using namespace std;
using namespace linphone;
using namespace reginfo;

namespace flexisip {

namespace RegistrationEvent {

Client::Client(const shared_ptr<Core> & core, const shared_ptr<const Address> &to) : mCore(core), mTo(to->clone()){
	
}

void Client::subscribe() {
	if (mSubscribeEvent){
		LOGE("Already subscribed.");
		return;
	}
	mCore->addListener(shared_from_this());
	mSubscribeEvent = mCore->createSubscribe(mTo, "reg", 600);
	mSubscribeEvent->addCustomHeader("Accept", "application/reginfo+xml");

	mSubscribeEvent->sendSubscribe(nullptr);
	
}

void Client::unsubscribe(){
	if (!mSubscribeEvent){
		LOGE("No subscribe.");
		return;
	}
	mSubscribeEvent->terminate();
	mCore->removeListener(shared_from_this());
	mSubscribeEvent = nullptr;
}

Client::~Client () {
	/* It is not possible to call shared_from_this() from here because we are in the destructor,
	 so not possible to remove us as a core listener. Too late.*/
	if (mSubscribeEvent){
		LOGA("RegistrationEvent::Client() destroyed while still subscription active.");
	}
}

void Client::setListener(ClientListener *listener){
	mListener = listener;
}

void Client::onNotifyReceived(
    const shared_ptr<Core> & lc,
    const shared_ptr<linphone::Event> & lev,
    const string & notifiedEvent,
    const shared_ptr<const Content> & body) {

	istringstream data(body->getStringBuffer());

	unique_ptr<Reginfo> ri(parseReginfo(data, Xsd::XmlSchema::Flags::dont_validate));

	for (const auto &registration : ri->getRegistration()) {
		list<shared_ptr<ParticipantDeviceIdentity>> participantDevices;
		size_t refreshed = 0;

		for (const auto &contact : registration.getContact()) {
			auto partDeviceAddr = Factory::get()->createAddress(contact.getUri());

			Contact::UnknownParamSequence ups = contact.getUnknownParam();

			for (const auto &param : ups) {
				if (param.getName() != "+org.linphone.specs") continue;
				string displayName = contact.getDisplayName() ? contact.getDisplayName()->c_str() : string("");
				shared_ptr<ParticipantDeviceIdentity> identity = Factory::get()->createParticipantDeviceIdentity(partDeviceAddr, displayName);
				identity->setCapabilityDescriptor(param);
				
				if (contact.getEvent() == reginfo::Event::refreshed){
					if (mListener) mListener->onRefreshed(identity);
					refreshed++;
				}
				participantDevices.push_back(identity);
				break;
			}
		}

		auto partAddr = Factory::get()->createAddress(registration.getAor());

		if (registration.getState() == Registration::StateType::terminated) {
			participantDevices.clear(); // We'll notify that 0 devices are registered.
		}
		if (refreshed != participantDevices.size()){
			if (mListener) mListener->onNotifyReceived(participantDevices);
		}/*otherwise it's useless */
	}
}

} // namespace RegistrationEvent

} // namespace flexisip
