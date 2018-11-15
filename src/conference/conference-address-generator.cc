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

#include <belle-sip/utils.h>

#include "conference-address-generator.hh"
#include "conference-server.hh"


using namespace flexisip;
using namespace std;


ConferenceAddressGenerator::ConferenceAddressGenerator (
	const shared_ptr<linphone::ChatRoom> chatRoom,
	shared_ptr<linphone::Address> conferenceFactoryAddr,
	const string &uuid,
	const string &path,
	ConferenceServer *conferenceServer
) : mChatRoom(chatRoom), mConferenceAddr(conferenceFactoryAddr), mUuid(uuid), mPath(path), mConferenceServer(conferenceServer) {}

void ConferenceAddressGenerator::run () {
	char token[17];
	ostringstream os;
	belle_sip_random_token(token, sizeof(token));
	os.str("");
	os << "chatroom-" << token;
	mConferenceAddr->setUsername(os.str());
	os.str("");
	os << "\"<urn:uuid:" << mUuid << ">\"";
	mConferenceAddr->setParam("+sip.instance", os.str());

	url_t *url = url_make(mHome.home(), mConferenceAddr->asStringUriOnly().c_str());
	RegistrarDb::get()->fetch(url, shared_from_this(), false, false);
}

void ConferenceAddressGenerator::onRecordFound (Record *r) {
	if (mState == State::Fetching) {
		if (r) {
			run();
		} else {
			mState = State::Binding;
			auto config = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
			mConferenceServer->bindChatRoom(
				mConferenceAddr->asStringUriOnly(),
				config->get<ConfigString>("transport")->read(),
				mUuid,
				shared_from_this()
			);
		}
	} else {
		const shared_ptr<ExtendedContact> ec = r->getExtendedContacts().front();
		string uri = ExtendedContact::urlToString(ec->mSipContact->m_url);
		shared_ptr<linphone::Address> addr = linphone::Factory::get()->createAddress(uri);
		shared_ptr<linphone::Address> gruuAddr = linphone::Factory::get()->createAddress(
			mConferenceAddr->asStringUriOnly()
		);
		gruuAddr->setUriParam("gr", addr->getUriParam("gr"));
		mChatRoom->setConferenceAddress(gruuAddr);
	}
}

void ConferenceAddressGenerator::onError () {
	mChatRoom->setConferenceAddress(nullptr);
}
