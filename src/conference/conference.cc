/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2017  Belledonne Communications SARL.

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

#include "conference.hh"



using namespace::std;

namespace flexisip{


Conference::Conference(ConferenceServer &server, const std::shared_ptr<const linphone::Address> &uri) : mServer(server), mUri(uri->clone()){
	shared_ptr<linphone::ConferenceParams> params = server.getCore()->createConferenceParams();
	// TODO: control audio enablement (not so useful actually).
	params->setVideoEnabled(mServer.getMediaConfig().videoEnabled);
	params->setLocalParticipantEnabled(false);
	params->setVideoEnabled(true);
	params->setLayout(linphone::ConferenceLayout::Grid);
	mConference = mServer.getCore()->createConferenceWithParams(params);
	// [workround] we need to recreate the same conference, but the username is not stored correctly in address.
	mConference->setUsername(uri->getUsername());
}

void Conference::addCall(const std::shared_ptr<linphone::Call> &call){
	LOGD("Conference [%s] : taking in charge new participant [%s]", mUri->asString().c_str(), call->getRemoteAddress()->asString().c_str());
		mConference->addParticipant(call);
}

}
