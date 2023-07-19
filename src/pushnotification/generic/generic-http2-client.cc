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

#include "generic-http2-client.hh"

#include "generic-http2-request.hh"
#include "generic-utils.hh"
#include "pushnotification/firebase/firebase-client.hh"

using namespace std;

namespace flexisip::pushnotification {

GenericHttp2Client::GenericHttp2Client(const sofiasip::Url& url,
                                       Method method,
                                       sofiasip::SuRoot& root,
                                       Service* pushService)
    : Client{pushService}, mHost{url.getHost()}, mPort{url.getPort(true)}, mPath(url.getPath()),
      mUrlParameters{url.getHeaders()}, mMethod{method} {
	ostringstream os{};
	os << "GenericHttp2Client[" << this << "]";
	mLogPrefix = os.str();
	SLOGD << mLogPrefix << ": constructing GenericHttp2Client";

	mHttp2Client = Http2Client::make(root, mHost, mPort);
}

void GenericHttp2Client::sendPush(const shared_ptr<Request>& request) {
	auto genericReq = dynamic_pointer_cast<GenericHttp2Request>(request);
	genericReq->setState(Request::State::InProgress);

	mHttp2Client->send(
	    genericReq, [this](const auto& req, const auto& resp) { this->onResponse(req, resp); },
	    [this](const auto& req) { this->onError(req); });
}

std::shared_ptr<Request> GenericHttp2Client::makeRequest(flexisip::pushnotification::PushType pType,
                                                         const shared_ptr<const PushInfo>& pInfo,
                                                         const map<std::string, std::shared_ptr<Client>>& allClients) {
	// Get the authentication key in case the native PNR is for the Firebase service.
	std::string authKey = GenericUtils::getFirebaseAuthKey(pType, pInfo, allClients);

	return make_shared<GenericHttp2Request>(pType, pInfo, mMethod, mHost, mPort, authKey, mPath, mUrlParameters);
}

void GenericHttp2Client::onResponse(const shared_ptr<HttpMessage>& request, const shared_ptr<HttpResponse>& response) {
	auto genericReq = dynamic_pointer_cast<GenericHttp2Request>(request);
	genericReq->setState(response->getStatusCode() == 200 ? Request::State::Successful : Request::State::Failed);

	if (genericReq->getState() == Request::State::Successful) {
		incrSentCounter();
	} else {
		incrFailedCounter();
	}
}

void GenericHttp2Client::onError(const shared_ptr<HttpMessage>& request) {
	auto genericReq = dynamic_pointer_cast<GenericHttp2Request>(request);
	genericReq->setState(Request::State::Failed);

	incrFailedCounter();
}

} // namespace flexisip::pushnotification
