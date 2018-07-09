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

#include "participant-capabilities-check.hh"


using namespace flexisip;
using namespace std;


ParticipantCapabilitiesCheck::ParticipantCapabilitiesCheck (
	const shared_ptr<linphone::ChatRoom> &cr,
	const shared_ptr<const linphone::Address> &deviceAddr,
	const list<shared_ptr<linphone::Address>> &list
) : mChatRoom(cr), mDeviceAddr(deviceAddr), mParticipantsList(list) {
	mIterator = mParticipantsList.begin();
}

void ParticipantCapabilitiesCheck::run () {
	url_t *url = url_make(mHome.home(), mIterator->get()->asStringUriOnly().c_str());
	RegistrarDb::get()->fetch(url, shared_from_this(), false, false);
}

void ParticipantCapabilitiesCheck::onRecordFound (Record *r) {
	if (r) {
		for (const shared_ptr<ExtendedContact> &ec : r->getExtendedContacts()) {
			string uri = ExtendedContact::urlToString(ec->mSipContact->m_url);
			shared_ptr<linphone::Address> addr = linphone::Factory::get()->createAddress(uri);
			if (!addr->getUriParam("gr").empty()
				&& (ec->getOrgLinphoneSpecs().find("groupchat") != string::npos)
			) {
				mParticipantsCompatibleList.push_back(*mIterator);
				break;
			}
		}
	}
	mIterator++;
	if (mIterator != mParticipantsList.end())
		run();
	else
		mChatRoom->addCompatibleParticipants(mDeviceAddr, mParticipantsCompatibleList);
}
