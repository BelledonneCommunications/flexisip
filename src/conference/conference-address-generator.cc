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

#include "conference-address-generator.hh"

#include <belle-sip/utils.h>

#include "conference-server.hh"
#include "conference/chatroom-prefix.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"

using namespace flexisip;
using namespace std;

ConferenceAddressGenerator::ConferenceAddressGenerator(const shared_ptr<linphone::ChatRoom>& chatRoom,
                                                       shared_ptr<linphone::Address>& conferenceFactoryAddr,
                                                       const string& path,
                                                       ConferenceServer* conferenceServer,
                                                       RegistrarDb& registrarDb)
    : mChatRoom(chatRoom), mConferenceAddr(conferenceFactoryAddr), mPath(path), mConferenceServer(conferenceServer),
      mRegistrarDb(registrarDb) {
}

void ConferenceAddressGenerator::run() {
	SipUri url(mConferenceAddr->asStringUriOnly());
	mRegistrarDb.fetch(url, shared_from_this(), false, false);
}

void ConferenceAddressGenerator::changeAddress() {
	char token[17];
	ostringstream os;

	belle_sip_random_token(token, sizeof(token));
	os << conference::CHATROOM_PREFIX << token;
	mConferenceAddr->setUsername(os.str());
}

void ConferenceAddressGenerator::onRecordFound(const std::shared_ptr<Record>& r) {
	if (mState == State::Fetching) {
		if (r && !r->isEmpty()) {
			SLOGW << "Conference address conflict detected, trying another random name.";
			changeAddress();
			run();
		} else {
			mState = State::Binding;
			auto& config = mConferenceServer->getServerConf();
			mConferenceServer->bindChatRoom(mConferenceAddr->asStringUriOnly(),
			                                config.get<ConfigString>("transport")->read(), shared_from_this());
		}
	} else {
		if (r->getExtendedContacts().empty()) throw FlexisipException{"conference address bind failed"};
		const shared_ptr<ExtendedContact> ec = *r->getExtendedContacts().latest();
		url_t* pub_gruu = r->getPubGruu(ec, mHome.home());
		if (!pub_gruu) throw FlexisipException{"conference does not have gruu address"};

		shared_ptr<linphone::Address> gruuAddr =
		    linphone::Factory::get()->createAddress(url_as_string(mHome.home(), pub_gruu));

		mChatRoom->setConferenceAddress(gruuAddr);
	}
}

void ConferenceAddressGenerator::onError(const SipStatus&) {
	mChatRoom->setConferenceAddress(nullptr);
}