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

#include "participant-registration-subscription.hh"


using namespace flexisip;
using namespace std;


ParticipantRegistrationSubscription::ParticipantRegistrationSubscription (
	const shared_ptr<const linphone::Address> &address,
	const shared_ptr<linphone::ChatRoom> &chatRoom
) : mParticipantAddress(address), mChatRoom(chatRoom) {}

void ParticipantRegistrationSubscription::onContactRegistered (const string &key, const string &uid) {
	shared_ptr<linphone::Address> deviceAddress = mParticipantAddress->clone();
	string gruu = uid;
	gruu = gruu.substr(gruu.find("\"<") + strlen("\"<"));
	gruu = gruu.substr(0, gruu.find(">"));
	deviceAddress->setUriParam("gr", gruu);
	mChatRoom->addParticipantDevice(mParticipantAddress, deviceAddress);
}

void ParticipantRegistrationSubscription::onRecordFound (Record *r) {
	// TODO
}
