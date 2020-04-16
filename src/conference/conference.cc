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
	params->enableVideo(true);
	params->enableLocalParticipant(false);
	mConference = mServer.getCore()->createConferenceWithParams(params);
}

void Conference::addCall(const std::shared_ptr<linphone::Call> &call){
	LOGD("Conference [%s] : taking in charge new participant [%s]", mUri->asString().c_str(), call->getRemoteAddress()->asString().c_str());
	mConference->addParticipant(call);
	if (call->getState() == linphone::Call::State::IncomingReceived){
		call->accept();
	}
}

}
