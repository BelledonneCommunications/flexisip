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

#include "registration-subscription.hh"

#include <memory>

#include "conference-server.hh"
#include "flexisip/registrar/registar-listeners.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"
#include "utils/string-utils.hh"

using namespace std;
using namespace linphone;

namespace flexisip {

RegistrationSubscription::RegistrationSubscription(bool checkCapabilities,
                                                   const shared_ptr<ChatRoom>& cr,
                                                   const shared_ptr<const Address>& participant)
    : mLogPrefix(LogManager::makeLogPrefixForInstance(this, "RegistrationSubscription")),
      mCheckCapabilities(checkCapabilities), mChatRoom(cr), mParticipant(participant->clone()) {
	LOGD << "Initialized for chatroom [" << cr.get() << "] and participant '" << participant->asStringUriOnly() << "'";
}

shared_ptr<ChatRoom> RegistrationSubscription::getChatRoom() const {
	return mChatRoom;
}

RegistrationSubscription::~RegistrationSubscription() {
	LOGD << "Destroy instance";
}

void RegistrationSubscription::notify(const list<shared_ptr<ParticipantDeviceIdentity>>& participantDevices) {
	LOGD << "Notifying chatroom [" << mChatRoom << "] of participant device list of " << participantDevices.size()
	     << " elements for participant '" << mParticipant->asStringUriOnly() << "'";
	mChatRoom->setParticipantDevices(mParticipant, participantDevices);
}

void RegistrationSubscription::notifyRegistration(const shared_ptr<const Address>& participantDevice) {
	LOGD << "Notifying chatroom [" << mChatRoom << "] that participant device '" << participantDevice->asStringUriOnly()
	     << "' has just registered";
	mChatRoom->notifyParticipantDeviceRegistration(participantDevice);
}

int RegistrationSubscription::getMaskFromSpecs(const string& specs) {
	unsigned int mask = 0;

	// Please excuse the following code that is a bit too basic in terms of parsing:
	if (specs.find("groupchat") != string::npos) mask |= (unsigned int)ChatRoom::Capabilities::Conference;
	if (specs.find("lime") != string::npos) mask |= (unsigned int)ChatRoom::Capabilities::Encrypted;
	if (specs.find("ephemeral") != string::npos) mask |= (unsigned int)ChatRoom::Capabilities::Ephemeral;
	return mask;
}

bool RegistrationSubscription::isContactCompatible(const string& specs) {
	if (!mCheckCapabilities) return true;

	// create a chat room mask with contact capabilities
	int mask = (int)ChatRoom::Capabilities::OneToOne;
	mask |= getMaskFromSpecs(specs);

	unsigned int chatRoomCapabilities = mChatRoom->getCapabilities();
	return (mask & chatRoomCapabilities) == chatRoomCapabilities;
}

/*
 * Redis implementation of RegistrationSubscription.
 */

OwnRegistrationSubscription::OwnRegistrationSubscription(const ConferenceServer& server,
                                                         const std::shared_ptr<linphone::ChatRoom>& cr,
                                                         const std::shared_ptr<const linphone::Address>& participant,
                                                         RegistrarDb& registrarDb)
    : RegistrationSubscription{server.capabilityCheckEnabled(), cr, participant},
      mLogPrefix{LogManager::makeLogPrefixForInstance(this, "OwnRegistrationSubscription")}, mRegistrarDb{registrarDb} {
	try {
		mParticipantAor = SipUri(participant->asStringUriOnly());
	} catch (const sofiasip::InvalidUrlError& e) {
		LOGE << "Invalid participant aor '" << participant->asStringUriOnly() << "': " << e.what();
	}
}

void OwnRegistrationSubscription::start() {
	if (mParticipantAor.empty()) return;

	mActive = true;
	/*First organise the fetch of the contacts belonging to this AOR, so that we can notify immediately*/
	mRegistrarDb.fetch(mParticipantAor, RegistrationSubscriptionFetchListener::shared_from_this(), true);

	/*Secondly subscribe for changes in the registration info of this participant*/
	mRegistrarDb.subscribe(Record::Key(mParticipantAor, mRegistrarDb.useGlobalDomain()),
	                       RegistrationSubscriptionListener::shared_from_this());
}

void OwnRegistrationSubscription::stop() {
	if (!mActive) return;
	mActive = false;
	mRegistrarDb.unsubscribe(Record::Key(mParticipantAor, mRegistrarDb.useGlobalDomain()),
	                         RegistrationSubscriptionListener::shared_from_this());
}

shared_ptr<Address> OwnRegistrationSubscription::getPubGruu(const shared_ptr<Record>& r,
                                                            const shared_ptr<ExtendedContact>& ec) {
	sofiasip::Home home;
	url_t* pub_gruu = r->getPubGruu(ec, home.home());
	if (pub_gruu) {
		char* pub_gruu_str = su_sprintf(home.home(), "<%s>", url_as_string(home.home(), pub_gruu));
		return Factory::get()->createAddress(pub_gruu_str);
	}
	return nullptr;
}

void OwnRegistrationSubscription::processRecord(const shared_ptr<Record>& r) {
	if (!mActive) return;
	list<shared_ptr<ParticipantDeviceIdentity>> compatibleParticipantDevices;
	if (r) {
		for (const auto& ec : r->getExtendedContacts()) {
			auto addr = getPubGruu(r, ec);
			if (!addr) continue;
			if (isContactCompatible(ec->getOrgLinphoneSpecs())) {
				shared_ptr<ParticipantDeviceIdentity> identity =
				    Factory::get()->createParticipantDeviceIdentity(addr, ec->getDeviceName());
				identity->setCapabilityDescriptor(list{string_utils::unquote(ec->getOrgLinphoneSpecs())});
				compatibleParticipantDevices.push_back(identity);
			} else {
				LOGD << "Participant device '" << addr->asStringUriOnly() << "' does not have required capabilities";
			}
		}
	}
	notify(compatibleParticipantDevices);
}

void OwnRegistrationSubscription::onRecordFound(const shared_ptr<Record>& r) {
	processRecord(r);
}

void OwnRegistrationSubscription::onContactRegistered(const shared_ptr<Record>& r, const string& uid) {
	if (!mActive) return;
	processRecord(r);

	if (uid.empty()) return;

	shared_ptr<ExtendedContact> ct = r->extractContactByUniqueId(uid);
	if (!ct) {
		LOGI << "No contact with uuid '" << uid << "' (it is not registered)";
		return;
	}
	shared_ptr<Address> pubGruu = getPubGruu(r, ct);
	if (pubGruu && isContactCompatible(ct->getOrgLinphoneSpecs())) notifyRegistration(pubGruu);
}

//=========================== External Registration Subscription ===================

ExternalRegistrationSubscription::ExternalRegistrationSubscription(const ConferenceServer& server,
                                                                   const shared_ptr<ChatRoom>& cr,
                                                                   const shared_ptr<const Address>& participant)
    : RegistrationSubscription(server.capabilityCheckEnabled(), cr, participant),
      Client(server.getRegEventClientFactory(), participant) {
	setListener(this);
}

void ExternalRegistrationSubscription::start() {
	subscribe();
}

void ExternalRegistrationSubscription::stop() {
	unsubscribe();
}

void ExternalRegistrationSubscription::onNotifyReceived(
    const list<shared_ptr<ParticipantDeviceIdentity>>& participantDevices) {
	auto compatibleParticipantDevices = participantDevices; // Make a copy
	// Remove uncompatible devices
	compatibleParticipantDevices.remove_if([this](shared_ptr<ParticipantDeviceIdentity>& deviceIdentity) {
		return !isContactCompatible(deviceIdentity->getCapabilityDescriptor());
	});
	notify(compatibleParticipantDevices);
}

void ExternalRegistrationSubscription::onRefreshed(const shared_ptr<ParticipantDeviceIdentity>& deviceIdentity) {
	if (isContactCompatible(deviceIdentity->getCapabilityDescriptor())) {
		notifyRegistration(deviceIdentity->getAddress());
	}
}

} // namespace flexisip