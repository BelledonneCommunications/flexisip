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
	url_t *url = url_make(mHome.home(), mParticipantAddress->asStringUriOnly().c_str());
	RegistrarDb::get()->fetchForGruu(url, uid, shared_from_this());
}

void ParticipantRegistrationSubscription::onRecordFound (Record *r) {
	if (!r)
		return;

	for (const shared_ptr<ExtendedContact> &ec : r->getExtendedContacts()) {
		string uri = ExtendedContact::urlToString(ec->mSipContact->m_url);
		shared_ptr<linphone::Address> addr = linphone::Factory::get()->createAddress(uri);
		if (!addr->getUriParam("gr").empty()
			&& (ec->getOrgLinphoneSpecs().find("groupchat") != string::npos)
		) {
			shared_ptr<linphone::Address> deviceAddress = mParticipantAddress->clone();
			deviceAddress->setUriParam("gr", addr->getUriParam("gr"));
			mChatRoom->addParticipantDevice(mParticipantAddress, deviceAddress);
		}
	}
}
