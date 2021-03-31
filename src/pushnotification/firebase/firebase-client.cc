/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include <flexisip/logmanager.hh>

#include "utils/string-utils.hh"

#include "firebase-client.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

// redundant declaration (required for C++14 compatibility)
constexpr const char* FirebaseClient::FIREBASE_ADDRESS;
constexpr const char* FirebaseClient::FIREBASE_PORT;

FirebaseClient::FirebaseClient(su_root_t& root) {
	ostringstream os{};
	os << "FirebaseClient[" << this << "]";
	mLogPrefix = os.str();
	SLOGD << mLogPrefix << ": constructing FirebaseClient";

	mHttp2Client = make_unique<Http2Client>(root, FIREBASE_ADDRESS, FIREBASE_PORT);
}

bool FirebaseClient::sendPush(const std::shared_ptr<Request>& req) {
	auto firebaseReq = dynamic_pointer_cast<FirebaseRequest>(req);

	firebaseReq->setState(Request::State::InProgress);
	mHttp2Client->send(
		firebaseReq, [this](const auto& req, const auto& resp) { this->onResponse(req, resp); },
		[this](const auto& req) { this->onError(req); });

	return true;
}

void FirebaseClient::onResponse(const std::shared_ptr<HttpMessage>& request,
								const std::shared_ptr<HttpResponse>& response) {
	SLOGD << mLogPrefix << ": onResponseCb " << response->toString();

	auto firebaseReq = dynamic_pointer_cast<FirebaseRequest>(request);
	if (response->getStatusCode() == 200) {
		firebaseReq->setState(Request::State::Successful);
	} else {
		firebaseReq->setState(Request::State::Failed);
	}
}

void FirebaseClient::onError(const std::shared_ptr<HttpMessage>& request) {
	SLOGD << mLogPrefix << ": onErrorCb";

	auto firebaseReq = dynamic_pointer_cast<FirebaseRequest>(request);
	firebaseReq->setState(Request::State::Failed);
}

} // namespace pushnotification
} // namespace flexisip
