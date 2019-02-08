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


using namespace flexisip;
using namespace std;
using namespace linphone;

RegistrationSubscription::RegistrationSubscription( const std::shared_ptr<linphone::ChatRoom> &cr, 
						    const std::shared_ptr<const linphone::Address> &participant)
	: mChatRoom(cr), mParticipant(participant->clone()) {
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

void RegistrationSubscription::notify(const std::list< shared_ptr<ParticipantDeviceIdentity> > & participantDevices){
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

OwnRegistrationSubscription::OwnRegistrationSubscription( const std::shared_ptr<linphone::ChatRoom> &cr, 
						    const std::shared_ptr<const linphone::Address> &participant)
	: RegistrationSubscription(cr, participant), mActive(false){
	mParticipantAor = url_make(mHome.home(), participant->asStringUriOnly().c_str());
	if (mParticipantAor == nullptr){
		LOGE("RegistrationSubscription(): invalid participant aor %s", participant->asStringUriOnly().c_str());
	}
}

void OwnRegistrationSubscription::start(){
	if (!mParticipantAor) return;
	
	mActive = true;
	/*First organise the fetch of the contacts belonging to this AOR, so that we can notify immediately*/
	RegistrarDb::get()->fetch(mParticipantAor, RegistrationSubscriptionFetchListener::shared_from_this(), true);
	
	/*Secondly subscribe for changes in the registration info of this participant*/
	string key = Record::defineKeyFromUrl(mParticipantAor);
	
	RegistrarDb::get()->subscribe(key, RegistrationSubscriptionListener::shared_from_this());
	
}

void OwnRegistrationSubscription::stop(){
	if (!mActive) return;
	mActive = false;
	string key = Record::defineKeyFromUrl(mParticipantAor);
	RegistrarDb::get()->unsubscribe(key, RegistrationSubscriptionListener::shared_from_this());
}

unsigned int OwnRegistrationSubscription::getContactCapabilities(const std::shared_ptr<ExtendedContact> &ec){
	unsigned int mask = 0;
	if (!url_has_param(ec->mSipContact->m_url, "gr")){
		return 0; //eliminate contacts without gruu, there is nothing we can do with them
	}
	string specs = ec->getOrgLinphoneSpecs();
	//Please excuse the following code that is a bit too basic in terms of parsing:
	if (specs.find("groupchat") != string::npos) mask |= (unsigned int)ChatRoomCapabilities::Conference;
	if (specs.find("lime") != string::npos) mask |= (unsigned int)ChatRoomCapabilities::Encrypted;
	return mask;
}

shared_ptr<Address> OwnRegistrationSubscription::getPubGruu(const shared_ptr<Record> &r, const shared_ptr<ExtendedContact> &ec){
	SofiaAutoHome home;
	url_t *pub_gruu = r->getPubGruu(ec, home.home());
	if (pub_gruu){
		char *pub_gruu_str = su_sprintf(home.home(), "<%s>", url_as_string(home.home(), pub_gruu));
		return linphone::Factory::get()->createAddress(pub_gruu_str);
	}
	return nullptr;
}

string OwnRegistrationSubscription::getDeviceName(const shared_ptr<ExtendedContact> &ec){
	const string &userAgent = ec->getUserAgent();
	size_t begin = userAgent.find("(");
	string deviceName;
	if (begin != string::npos) {
		size_t end = userAgent.find(")", begin);
		if (end != string::npos){
			deviceName = userAgent.substr(begin + 1, end - (begin + 1));
		}
	}
	return deviceName;
}

void OwnRegistrationSubscription::processRecord(const std::shared_ptr<Record> &r){
	if (!mActive) return;
	list<shared_ptr<ParticipantDeviceIdentity>> compatibleParticipantDevices;
	if (r){
		for (const shared_ptr<ExtendedContact> &ec : r->getExtendedContacts()) {
			auto addr = getPubGruu(r, ec);
			if (!addr) continue;
			if ((getContactCapabilities(ec) & mChatroomRequestedCapabilities) == mChatroomRequestedCapabilities){
				shared_ptr<ParticipantDeviceIdentity> identity = linphone::Factory::get()->createParticipantDeviceIdentity(
					addr, getDeviceName(ec));
				compatibleParticipantDevices.push_back(identity);
			}else LOGD("OwnRegistrationSubscription::processRecord(): %s does not have the required capabilities.", addr->asStringUriOnly().c_str());
		}
	}
	notify(compatibleParticipantDevices);
}

void OwnRegistrationSubscription::onRecordFound (const std::shared_ptr<Record> &r) {
	processRecord(r);
}

void OwnRegistrationSubscription::onError (){
}

void OwnRegistrationSubscription::onInvalid (){
}

void OwnRegistrationSubscription::onContactRegistered(const std::shared_ptr<Record> &r, const std::string &uid){
	if (!mActive) return;
	processRecord(r);
	
	if (uid.empty()) return;
	
	shared_ptr<ExtendedContact> ct = r->extractContactByUniqueId(uid);
	if (!ct){
		LOGI("OwnRegistrationSubscription::onContactRegistered(): no contact with uuid %s, it has unregistered.", uid.c_str());
		return;
	}
	shared_ptr<Address> pubGruu = getPubGruu(r, ct);
	if (pubGruu) notifyRegistration(pubGruu);
}


