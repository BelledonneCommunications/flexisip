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

#include "apple-client.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

// redundant declaration (required for C++14 compatibility)
constexpr const char* AppleClient::APN_DEV_ADDRESS;
constexpr const char* AppleClient::APN_PROD_ADDRESS;
constexpr const char* AppleClient::APN_PORT;

AppleClient::AppleClient(su_root_t& root, const string& trustStorePath, const string& certPath,
						 const string& certName) {
	ostringstream os{};
	os << "AppleClient[" << this << "]";
	mLogPrefix = os.str();
	SLOGD << mLogPrefix << ": constructing AppleClient";

	const auto apn_server = (certName.find(".dev") != string::npos) ? APN_DEV_ADDRESS : APN_PROD_ADDRESS;
	mHttp2Client = make_unique<Http2Client>(root, apn_server, APN_PORT, trustStorePath, certPath);
}

void AppleClient::sendPush(const std::shared_ptr<Request>& req) {
	auto appleReq = dynamic_pointer_cast<AppleRequest>(req);

	auto topicLen = appleReq->getAppIdentifier().rfind(".");
	auto apnsTopic = appleReq->getAppIdentifier().substr(0, topicLen);
	// Check whether the appId is compatible with the payload type
	auto endsWithVoip = StringUtils::endsWith(apnsTopic, ".voip");
	if ((appleReq->mPayloadType == ApplePushType::Pushkit && !endsWithVoip) ||
		(appleReq->mPayloadType != ApplePushType::Pushkit && endsWithVoip)) {
		SLOGE << mLogPrefix << ": apns-topic [" << apnsTopic << "] not compatible with payload type ["
			  << toString(appleReq->mPayloadType) << "]. Aborting";

		appleReq->setState(Request::State::Failed);
		return;
	}

	auto host = mHttp2Client->getHost();
	appleReq->getHeaders().add("host", host);

	appleReq->setState(Request::State::InProgress);
	mHttp2Client->send(
		appleReq, [this](const auto& req, const auto& resp) { this->onResponse(req, resp); },
		[this](const auto& req) { this->onError(req); });
}

void AppleClient::onResponse(const std::shared_ptr<HttpMessage>& request,
							 const std::shared_ptr<HttpResponse>& response) {
	SLOGD << mLogPrefix << ": onResponseCb " << response->toString();

	auto appleReq = dynamic_pointer_cast<AppleRequest>(request);
	if (response->getStatusCode() == 200) {
		appleReq->setState(Request::State::Successful);
	} else {
		appleReq->setState(Request::State::Failed);
	}
}

void AppleClient::onError(const std::shared_ptr<HttpMessage>& request) {
	SLOGD << mLogPrefix << ": onErrorCb";

	auto appleReq = dynamic_pointer_cast<AppleRequest>(request);
	appleReq->setState(Request::State::Failed);
}

} // namespace pushnotification
} // namespace flexisip
