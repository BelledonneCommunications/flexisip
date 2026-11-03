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

#include "call-transfer-listener.hh"

#include "flexisip/logmanager.hh"

using namespace std;

namespace flexisip::b2bua {

void b2bua::CallTransferListener::onTransferStateChanged(const std::shared_ptr<linphone::Call>& call,
                                                         linphone::Call::State state) {
	LOGD << "Call " << call << " transfer state changed to: " << static_cast<int>(state);

	string body{};
	switch (state) {
		case linphone::Call::State::OutgoingProgress:
			body = "SIP/2.0 100 Trying\r\n";
			break;
		case linphone::Call::State::Connected:
			body = "SIP/2.0 200 Ok\r\n";
			break;
		case linphone::Call::State::Error:
			body = "SIP/2.0 500 Internal Server Error\r\n";
			LOGD << "Forward NOTIFY request with body \"" << body.substr(0, body.size() - 2)
			     << "\" because we cannot yet distinguish all cases (603 Decline, 503 Service Unavailable, etc.)";
			break;
		default:
			LOGW << "Unable to forward NOTIFY request, case " << static_cast<int>(state) << " is not implemented";
			return;
	}
	sendNotify(body);

	if (state == linphone::Call::State::Connected or state == linphone::Call::State::Error) {
		// Terminate the REFER subscription once the final NOTIFY has been sent.
		if (mNotifyEvent) mNotifyEvent->terminate();
	}
}

void b2bua::CallTransferListener::sendNotify(const std::string& body) {
	const auto peerCall = mPeerCall.lock();
	if (!peerCall) {
		LOGW << "Unable to forward NOTIFY request with body \"(" << body << "\", peer call has been freed";
		return;
	}

	if (!mNotifyEvent) {
		mNotifyEvent = peerCall->createNotify("refer");
		if (!mNotifyEvent) {
			LOGE << "Error while forwarding NOTIFY request, could not create request";
			return;
		}
	}

	const auto content = linphone::Factory::get()->createContent();
	if (!content) {
		LOGE << "Error while forwarding NOTIFY request, could not create content object";
		return;
	}
	content->setType("message");
	content->setSubtype("sipfrag");
	content->setUtf8Text(body);

	if (mNotifyEvent->notify(content) != 0) {
		// Drop the event: the subscription can no longer be used, a new one is created for the next request.
		LOGE << "Error while forwarding NOTIFY request, could not send request";
		mNotifyEvent.reset();
	}
}

} // namespace flexisip::b2bua