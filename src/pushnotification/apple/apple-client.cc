/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "apple-client.hh"

#include <flexisip/logmanager.hh>

#include "pushnotification/apple/apple-request.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

std::string AppleClient::APN_DEV_ADDRESS{"api.development.push.apple.com"};
std::string AppleClient::APN_PROD_ADDRESS{"api.push.apple.com"};
std::string AppleClient::APN_PORT{"443"};

AppleClient::AppleClient(sofiasip::SuRoot& root,
                         const std::string& trustStorePath,
                         const std::string& certPath,
                         const std::string& certName,
                         const Service* service)
    : Client{service} {
	ostringstream os{};
	os << "AppleClient[" << this << "]";
	mLogPrefix = os.str();
	SLOGD << mLogPrefix << ": constructing AppleClient";

	const auto apn_server = (certName.find(".dev") != string::npos) ? APN_DEV_ADDRESS : APN_PROD_ADDRESS;
	mHttp2Client = Http2Client::make(root, apn_server, APN_PORT, trustStorePath, certPath);
}

void AppleClient::sendPush(const std::shared_ptr<Request>& req) {
	auto appleReq = dynamic_pointer_cast<AppleRequest>(req);

	auto host = mHttp2Client->getHost();
	appleReq->getHeaders().add("host", host);

	appleReq->setState(Request::State::InProgress);
	mHttp2Client->send(
	    appleReq, [this](const auto& req, const auto& resp) { this->onResponse(req, resp); },
	    [this](const auto& req) { this->onError(req); });
}

void AppleClient::onResponse(const std::shared_ptr<HttpMessage>& request,
                             const std::shared_ptr<HttpResponse>& response) {
	auto appleReq = dynamic_pointer_cast<AppleRequest>(request);
	appleReq->setState(response->getStatusCode() == 200 ? Request::State::Successful : Request::State::Failed);

	if (appleReq->getState() == Request::State::Successful) {
		incrSentCounter();
	} else {
		incrFailedCounter();
	}
}

void AppleClient::onError(const std::shared_ptr<HttpMessage>& request) {
	auto appleReq = dynamic_pointer_cast<AppleRequest>(request);
	appleReq->setState(Request::State::Failed);

	incrFailedCounter();
}

} // namespace pushnotification
} // namespace flexisip
