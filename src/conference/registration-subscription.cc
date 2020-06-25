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

#include "registration-subscription.hh"
#include "conference-server.hh"

using namespace flexisip;
using namespace std;
using namespace linphone;

RegistrationSubscription::RegistrationSubscription(const ConferenceServer & server, const shared_ptr<ChatRoom> &cr,
						    const shared_ptr<const Address> &participant)
	: mServer(server), mChatRoom(cr), mParticipant(participant->clone()) {
	LOGD("RegistrationSubscription [%p] for chatroom [%p] and participant [%s] initialized.", this, cr.get(),
	     participant->asStringUriOnly().c_str());
	mChatroomRequestedCapabilities = cr->getCapabilities() & ~(int)ChatRoomCapabilities::OneToOne;
}

shared_ptr<ChatRoom> RegistrationSubscription::getChatRoom()const{
	return mChatRoom;
}

RegistrationSubscription::~RegistrationSubscription(){
	LOGD("RegistrationSubscription [%p] destroyed.", this);
}

void RegistrationSubscription::notify(const list< shared_ptr<ParticipantDeviceIdentity> > & participantDevices){
	LOGD("RegistrationSubscription: notifying chatroom [%p] of participant device list of [%i] elements for participant [%s].",
	     mChatRoom.get(), (int)participantDevices.size(), mParticipant->asStringUriOnly().c_str());
	mChatRoom->setParticipantDevices(mParticipant, participantDevices);
}

void RegistrationSubscription::notifyRegistration(const shared_ptr<Address> &participantDevice){
	LOGD("RegistrationSubscription: notifying chatroom [%p] that participant-device [%s] has just registered.",
	     mChatRoom.get(), participantDevice->asStringUriOnly().c_str());
	mChatRoom->notifyParticipantDeviceRegistration(participantDevice);
}


/*
 * Redis implementation of RegistrationSubscription.
 */

OwnRegistrationSubscription::OwnRegistrationSubscription(const ConferenceServer & server, const std::shared_ptr<linphone::ChatRoom> &cr,
						    const std::shared_ptr<const linphone::Address> &participant)
	: RegistrationSubscription(server, cr, participant) {
	try {
		mParticipantAor = SipUri(participant->asStringUriOnly());
	} catch (const invalid_argument &e) {
		LOGE("RegistrationSubscription(): invalid participant aor %s: %s",
			 participant->asStringUriOnly().c_str(),
			 e.what()
		);
	}
}

void OwnRegistrationSubscription::start(){
	if (mParticipantAor.empty()) return;

	mActive = true;
	/*First organise the fetch of the contacts belonging to this AOR, so that we can notify immediately*/
	RegistrarDb::get()->fetch(mParticipantAor, RegistrationSubscriptionFetchListener::shared_from_this(), true);

	/*Secondly subscribe for changes in the registration info of this participant*/
	RegistrarDb::get()->subscribe(mParticipantAor, RegistrationSubscriptionListener::shared_from_this());
}

void OwnRegistrationSubscription::stop(){
	if (!mActive) return;
	mActive = false;
	string key = Record::defineKeyFromUrl(mParticipantAor.get());
	RegistrarDb::get()->unsubscribe(key, RegistrationSubscriptionListener::shared_from_this());
}

unsigned int OwnRegistrationSubscription::getContactCapabilities(const shared_ptr<ExtendedContact> &ec){
	unsigned int mask = 0;
	string specs = ec->getOrgLinphoneSpecs();
	//Please excuse the following code that is a bit too basic in terms of parsing:
	if (specs.find("groupchat") != string::npos) mask |= (unsigned int)ChatRoomCapabilities::Conference;
	if (specs.find("lime") != string::npos) mask |= (unsigned int)ChatRoomCapabilities::Encrypted;
	return mask;
}

shared_ptr<Address> OwnRegistrationSubscription::getPubGruu(const shared_ptr<Record> &r, const shared_ptr<ExtendedContact> &ec){
	sofiasip::Home home;
	url_t *pub_gruu = r->getPubGruu(ec, home.home());
	if (pub_gruu){
		char *pub_gruu_str = su_sprintf(home.home(), "<%s>", url_as_string(home.home(), pub_gruu));
		return Factory::get()->createAddress(pub_gruu_str);
	}
	return nullptr;
}

string OwnRegistrationSubscription::getDeviceName(const shared_ptr<ExtendedContact> &ec){
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

bool OwnRegistrationSubscription::isContactCompatible(const shared_ptr<ExtendedContact> &ec){
	return !mServer.capabilityCheckEnabled() || (getContactCapabilities(ec) & mChatroomRequestedCapabilities) == mChatroomRequestedCapabilities;
}

void OwnRegistrationSubscription::processRecord(const shared_ptr<Record> &r){
	if (!mActive) return;
	list<shared_ptr<ParticipantDeviceIdentity>> compatibleParticipantDevices;
	if (r){
		for (const shared_ptr<ExtendedContact> &ec : r->getExtendedContacts()) {
			auto addr = getPubGruu(r, ec);
			if (!addr) continue;
			if (isContactCompatible(ec)){
				shared_ptr<ParticipantDeviceIdentity> identity = Factory::get()->createParticipantDeviceIdentity(
					addr, getDeviceName(ec));
				compatibleParticipantDevices.push_back(identity);
			} else LOGD("OwnRegistrationSubscription::processRecord(): %s does not have the required capabilities.", addr->asStringUriOnly().c_str());
		}
	}
	notify(compatibleParticipantDevices);
}

void OwnRegistrationSubscription::onRecordFound (const shared_ptr<Record> &r) {
	processRecord(r);
}

void OwnRegistrationSubscription::onContactRegistered(const shared_ptr<Record> &r, const string &uid){
	if (!mActive) return;
	processRecord(r);

	if (uid.empty()) return;

	shared_ptr<ExtendedContact> ct = r->extractContactByUniqueId(uid);
	if (!ct){
		LOGI("OwnRegistrationSubscription::onContactRegistered(): no contact with uuid %s, it has unregistered.", uid.c_str());
		return;
	}
	shared_ptr<Address> pubGruu = getPubGruu(r, ct);
	if (pubGruu && isContactCompatible(ct)) notifyRegistration(pubGruu);
}
