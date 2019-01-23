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

#include "participant-devices-search.hh"


using namespace flexisip;
using namespace std;


ParticipantDevicesSearch::ParticipantDevicesSearch (
	const shared_ptr<linphone::ChatRoom> &cr,
	const shared_ptr<const linphone::Address> &uri
) : mChatRoom(cr), mSipUri(uri) {}

void ParticipantDevicesSearch::run () {
	url_t *url = url_make(mHome.home(), mSipUri->asStringUriOnly().c_str());
	RegistrarDb::get()->fetch(url, shared_from_this(), false, false);
}

void ParticipantDevicesSearch::onRecordFound (Record *r) {
	if (!r) return;

	list<shared_ptr<linphone::ParticipantDeviceIdentity>> listDeviceIdentities;
	for (const shared_ptr<ExtendedContact> &ec : r->getExtendedContacts()) {
		string uri = ExtendedContact::urlToString(ec->mSipContact->m_url);
		shared_ptr<linphone::Address> addr = linphone::Factory::get()->createAddress(uri);
		if (!addr->getUriParam("gr").empty()
			&& (ec->getOrgLinphoneSpecs().find("groupchat") != string::npos)
		) {
			shared_ptr<linphone::Address> deviceAddr = linphone::Factory::get()->createAddress(
				mSipUri->asStringUriOnly()
			);

			deviceAddr->setUriParam("gr", addr->getUriParam("gr"));

			const string &userAgent = ec->getUserAgent();
			size_t begin = userAgent.find("(");
			string deviceName = "";
			if (begin != string::npos) {
				size_t end = userAgent.find(")", begin);
				deviceName = userAgent.substr(begin + 1, end - (begin + 1));
			}

			shared_ptr<linphone::ParticipantDeviceIdentity> identity = linphone::Factory::get()->createParticipantDeviceIdentity(deviceAddr, deviceName);
			listDeviceIdentities.push_back(identity);
		}
	}

	mChatRoom->setParticipantDevices(mSipUri, listDeviceIdentities);
}
