/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "firebase-v1-client.hh"

#include "flexisip/logmanager.hh"
#include "firebase-v1-authentication-manager.hh"
#include "firebase-v1-request.hh"
#include "utils/transport/http/http2client.hh"

using namespace std;

namespace flexisip::pushnotification {

std::string FirebaseV1Client::FIREBASE_ADDRESS{"fcm.googleapis.com"};
std::string FirebaseV1Client::FIREBASE_PORT{"443"};

FirebaseV1Client::FirebaseV1Client(sofiasip::SuRoot& root,
                                   std::shared_ptr<FirebaseV1AuthenticationManager>&& authenticationManager,
                                   const Service* service)
    : Client{service}, mProjectId(authenticationManager->getProjectId()) {
	ostringstream os{};
	os << "FirebaseV1Client[" << this << "]";
	mLogPrefix = os.str();
	SLOGD << mLogPrefix << ": constructing FirebaseV1Client";

	mHttp2Client = Http2Client::make(root, FIREBASE_ADDRESS, FIREBASE_PORT, std::move(authenticationManager));
}

std::shared_ptr<Request> FirebaseV1Client::makeRequest(PushType pType,
                                                       const shared_ptr<const PushInfo>& pInfo,
                                                       const map<std::string, std::shared_ptr<Client>>&) {
	return make_shared<FirebaseV1Request>(pType, pInfo, mProjectId);
}

void FirebaseV1Client::sendPush(const std::shared_ptr<Request>& req) {
	auto firebaseReq = dynamic_pointer_cast<FirebaseV1Request>(req);

	firebaseReq->setState(Request::State::InProgress);
	mHttp2Client->send(
	    firebaseReq, [this](const auto& req, const auto& resp) { this->onResponse(req, resp); },
	    [this](const auto& req) { this->onError(req); });
}

void FirebaseV1Client::onResponse(const std::shared_ptr<HttpMessage>& request,
                                  const std::shared_ptr<HttpResponse>& response) {
	auto firebaseReq = dynamic_pointer_cast<FirebaseV1Request>(request);
	firebaseReq->setState(response->getStatusCode() == 200 ? Request::State::Successful : Request::State::Failed);

	if (firebaseReq->getState() == Request::State::Successful) {
		incrSentCounter();
	} else {
		incrFailedCounter();
	}
}

void FirebaseV1Client::onError(const std::shared_ptr<HttpMessage>& request) {
	auto firebaseReq = dynamic_pointer_cast<FirebaseV1Request>(request);
	firebaseReq->setState(Request::State::Failed);

	incrFailedCounter();
}

} // namespace flexisip::pushnotification
