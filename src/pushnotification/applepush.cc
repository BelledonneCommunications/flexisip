/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

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

#include <algorithm>
#include <array>
#include <iomanip>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <array>

#include <nghttp2/nghttp2ver.h>

#include <flexisip/common.hh>

#include "utils/string-utils.hh"

#include "applepush.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

AppleRequest::AppleRequest(const PushInfo &info) : Request(info.mAppId, "apple"), mPayloadType{info.mApplePushType} {
	const string &deviceToken = info.mDeviceToken;
	const string &msg_id = info.mAlertMsgId;
	const string &arg = info.mFromName.empty() ? info.mFromUri : info.mFromName;
	const string &sound = info.mAlertSound;
	const string &callid = info.mCallId;
	string date = getPushTimeStamp();
	int nwritten = 0;

	mPayload.assign(MAXPAYLOAD_SIZE + 1, '\0');

	mDeviceToken = deviceToken;
	checkDeviceToken();

	string customPayload = (info.mCustomPayload.empty()) ? "{}" : info.mCustomPayload;

	switch (info.mApplePushType) {
		case ApplePushType::Unknown:
			throw invalid_argument{"Apple push type not set"};
		case ApplePushType::Pushkit: {
			// We also need msg_id and callid in case the push is received but the device cannot register
			constexpr auto rawPayload = R"json({
				"aps": {
					"sound": "",
					"loc-key": "%s",
					"loc-args": ["%s"],
					"call-id": "%s",
					"uuid": %s,
					"send-time": "%s"
				},
				"from-uri": "%s",
				"display-name": "%s",
				"pn_ttl": %d,
				"customPayload": %s
			})json";
			nwritten = snprintf(mPayload.data(), mPayload.size(), rawPayload,
				msg_id.c_str(),
				arg.c_str(),
				callid.c_str(),
				quoteStringIfNeeded(info.mUid).c_str(),
				date.c_str(),
				info.mFromUri.c_str(),
				info.mFromName.c_str(),
				info.mTtl,
				customPayload.c_str()
			);
			break;
		}
		case ApplePushType::Background: {
			// Use a normal push notification with content-available set to 1, no alert, no sound.
			constexpr auto rawPayload = R"json({
				"aps": {
					"badge": 0,
					"content-available": 1,
					"loc-key": "%s",
					"loc-args": ["%s"],
					"call-id": "%s",
					"uuid": %s,
					"send-time": "%s"
				},
				"from-uri": "%s",
				"display-name": "%s",
				"pn_ttl": %d,
				"customPayload": %s
			})json";
			nwritten = snprintf(mPayload.data(), mPayload.size(), rawPayload,
				msg_id.c_str(),
				arg.c_str(),
				callid.c_str(),
				quoteStringIfNeeded(info.mUid).c_str(),
				date.c_str(),
				info.mFromUri.c_str(),
				info.mFromName.c_str(),
				info.mTtl,
				customPayload.c_str()
			);
			break;
		}
		case ApplePushType::RemoteBasic: {
			/* some apps don't want the push to update the badge - but if they do,
			we always put the badge value to 1 because we want to notify the user that
			he/she has unread messages even if we do not know the exact count */
			constexpr auto rawPayload = R"json({
				"aps": {
					"alert": {
						"loc-key": "%s",
						"loc-args": ["%s"]
					},
					"sound": "%s",
					"badge": %d
				},
				"from-uri": "%s",
				"display-name": "%s",
				"call-id": "%s",
				"pn_ttl": %d,
				"uuid": %s,
				"send-time": "%s",
				"customPayload": %s
			})json";
			nwritten = snprintf(mPayload.data(), mPayload.size(), rawPayload,
				msg_id.c_str(),
				arg.c_str(),
				sound.c_str(),
				(info.mNoBadge ? 0 : 1),
				info.mFromUri.c_str(),
				info.mFromName.c_str(),
				callid.c_str(),
				info.mTtl,
				quoteStringIfNeeded(info.mUid).c_str(),
				date.c_str(),
				customPayload.c_str()
			);
			break;
		}
		case ApplePushType::RemoteWithMutableContent: {
			/* some apps don't want the push to update the badge - but if they do,
			we always put the badge value to 1 because we want to notify the user that
			he/she has unread messages even if we do not know the exact count */
			constexpr auto rawPayload = R"json({
				"aps": {
					"alert": {
						"loc-key": "%s",
						"loc-args": ["%s"]
					},
					"sound": "%s",
					"mutable-content": 1,
					"badge": %d
				},
				"from-uri": "%s",
				"display-name": "%s",
				"call-id": "%s",
				"pn_ttl": %d,
				"uuid": %s,
				"send-time": "%s",
				"chat-room-addr": "%s",
				"customPayload": %s
			})json";
			nwritten = snprintf(mPayload.data(), mPayload.size(), rawPayload,
				msg_id.c_str(),
				arg.c_str(),
				sound.c_str(),
				(info.mNoBadge ? 0 : 1),
				info.mFromUri.c_str(),
				info.mFromName.c_str(),
				callid.c_str(),
				info.mTtl,
				quoteStringIfNeeded(info.mUid).c_str(),
				date.c_str(),
				info.mChatRoomAddr.c_str(),
				customPayload.c_str()
			);
			break;
		}
	}

	SLOGD << "PNR " << this << " payload is " << mPayload.data();
	if (nwritten < 0 || unsigned(nwritten) >= mPayload.size()) {
		SLOGE << "PNR " << this << " cannot be sent because the payload size is higher than " << MAXPAYLOAD_SIZE;
		mPayload.clear();
		return;
	}
	mPayload.resize(nwritten);
}

void AppleRequest::checkDeviceToken() const {
	static const regex tokenMatch{R"regex([0-9A-Za-z]+)regex"};
	if (!regex_match(mDeviceToken, tokenMatch) || mDeviceToken.size() != DEVICE_BINARY_SIZE*2) {
		throw runtime_error("ApplePushNotification: Invalid deviceToken");
	}
}

AppleClient::PnrContext::PnrContext(AppleClient &client, const std::shared_ptr<AppleRequest> &pnr, unsigned timeout /* s */) noexcept
	: mPnr{pnr} {
	mTimer = make_unique<sofiasip::Timer>(&client.mRoot, timeout * 1000);
	mTimer->set([&client, this] () {
		SLOGE << client.mLogPrefix << ": request timeout.";
		mPnr->setState(Request::State::Failed);
		auto &pnrToRemove = mPnr;
		auto it = find_if(
			client.mPNRs.begin(), client.mPNRs.end(),
			[&pnrToRemove](const auto &e){return e.second.mPnr == pnrToRemove;}
		);
		client.mPNRs.erase(it);
	});
}

AppleClient::AppleClient(su_root_t &root) : mRoot{root} {
	ostringstream os{};
	os << "AppleClient[" << this << "]";
	mLogPrefix = os.str();
	SLOGD << mLogPrefix << ": constructing AppleClient";
}

bool AppleClient::sendPush(const std::shared_ptr<Request> &req) {
	auto appleReq = dynamic_pointer_cast<AppleRequest>(req);
	mPendingPNRs.emplace(move(appleReq));

	/*if (mState != State::Connected) {
		if (mState == State::Disconnected) connect();
		return true;
	} TODO */

	return sendAllPendingPNRs();
}

bool AppleClient::sendAllPendingPNRs() {
	//TODO
	/*auto pnrSent = false;
	while (!mPendingPNRs.empty()) {
		auto appleReq = move(mPendingPNRs.front());
		mPendingPNRs.pop();

		auto host = mConn->getPort() == "443"
			? mConn->getHost()
			: mConn->getHost() + ":" + mConn->getPort();
		auto path = string{"/3/device/"} + appleReq->getDeviceToken();
		auto topicLen = appleReq->getAppIdentifier().rfind(".");
		auto apnsTopic = appleReq->getAppIdentifier().substr(0, topicLen);

		// Check whether the appId is compatible with the payload type
		auto endsWithVoip = StringUtils::endsWith(apnsTopic, ".voip");
		if ((appleReq->mPayloadType == ApplePushType::Pushkit && !endsWithVoip)
				|| (appleReq->mPayloadType != ApplePushType::Pushkit && endsWithVoip)) {
			SLOGE << mLogPrefix << ": apns-topic [" << apnsTopic << "] not compatible with payload type ["
				<< toString(appleReq->mPayloadType) << "]. Aborting";
			continue;
		}

		HeaderStore hStore{};
		hStore.add( ":method"         , "POST"     );
		hStore.add( ":scheme"         , "https"    );
		hStore.add( ":path"           , move(path) );
		hStore.add( "host"            , move(host) );
		hStore.add( "apns-expiration" , "0"        );
		hStore.add( "apns-topic"      , apnsTopic  );
		auto hList = hStore.makeHeaderList();

		DataProvider dataProv{appleReq->getData()};
		auto streamId = nghttp2_submit_request(mHttpSession.get(), nullptr, hList.data(), hList.size(), dataProv.getCStruct(), nullptr);
		if (streamId < 0) {
			SLOGE << mLogPrefix << ": push request submit failed. reason=[" << nghttp2_strerror(streamId) << "]";
			continue;
		}
		auto logPrefix = string{mLogPrefix} + "[" + to_string(streamId) + "]";

		ostringstream msg{};
		msg << logPrefix << ": sending PNR " << appleReq << ":\n"
			<< hStore.toString() << endl;
		msg.write(appleReq->getData().data(), appleReq->getData().size());
		SLOGD << msg.str();

		auto status = nghttp2_session_send(mHttpSession.get());
		if (status < 0) {
			SLOGE << logPrefix << ": push request sending failed. reason=[" << nghttp2_strerror(status) << "]";
			continue;
		}

		mPNRs.emplace(streamId, PnrContext{*this, appleReq, sPnrTimeout});
		appleReq->setState(Request::State::InProgress);

		pnrSent = true;
	}

	if (pnrSent) resetIdleTimer();*/
	return true;
}

const char *Http2Tools::frameTypeToString(uint8_t frameType) noexcept {
	switch(frameType) {
		case NGHTTP2_DATA:          return "DATA";
		case NGHTTP2_HEADERS:       return "HEADERS";
		case NGHTTP2_PRIORITY:      return "PRIORITY";
		case NGHTTP2_RST_STREAM:    return "RST_STREAM";
		case NGHTTP2_SETTINGS:      return "SETTINGS";
		case NGHTTP2_PUSH_PROMISE:  return "PUSH_PROMISE";
		case NGHTTP2_PING:          return "PING";
		case NGHTTP2_GOAWAY:        return "GOAWAY";
		case NGHTTP2_WINDOW_UPDATE: return "WINDOW_UPDATE";
		case NGHTTP2_CONTINUATION:  return "CONTINUATION";
#if NGHTTP2_VERSION_NUM >= 0x010a00 // v1.10.0
		case NGHTTP2_ALTSVC:        return "ALTSVC";
#endif
#if NGHTTP2_VERSION_NUM >= 0x012100 // v1.33.0
		case NGHTTP2_ORIGIN:        return "ORIGIN";
#endif
	}
	return "UNKNOWN";
}

std::string Http2Tools::printFlags(uint8_t flags) noexcept {
	array<const char *, 4> flagsAsStr{};

	auto len = 0;
	if (flags & NGHTTP2_FLAG_END_STREAM) flagsAsStr.at(len++) = "END_STREAM";
	if (flags & NGHTTP2_FLAG_END_HEADERS) flagsAsStr.at(len++) = "END_HEADERS";
	if (flags & NGHTTP2_FLAG_ACK) flagsAsStr.at(len++) = "ACK";
	if (flags & NGHTTP2_FLAG_PADDED) flagsAsStr.at(len++) = "PADDED";

	string res{};
	for (auto i = 0; i < len; ++i) {
		if (i != 0) res += " | ";
		res += flagsAsStr.at(i);
	}
	return res;
}

} // end of pushnotification namespace
} // end of flexisip namespace


using namespace flexisip::pushnotification;


std::ostream &operator<<(std::ostream &os, const nghttp2_frame &frame) noexcept {
	os << Http2Tools::frameTypeToString(frame.hd.type) << endl;
	os << "streamId: " << frame.hd.stream_id << endl;
	os << hex << showbase;
	os << "flags: " << int(frame.hd.flags) << " [" << Http2Tools::printFlags(frame.hd.flags) << "]" << endl;
	os << dec << noshowbase;
	switch (frame.hd.type) {
		case NGHTTP2_HEADERS:
			os << endl;
			if (frame.headers.nvlen > 0) {
				for (unsigned i = 0; i < frame.headers.nvlen; ++i) {
					const auto &nva = frame.headers.nva[i];
					os << nva.name << ": " << nva.value << endl;
				}
			} else {
				os << "<empty>" << endl;
			}
			break;
		case NGHTTP2_RST_STREAM: {
			const auto &error_code = frame.rst_stream.error_code;
			os << "errorCode: " << error_code;
#if NGHTTP2_VERSION_NUM >= 0x010900 // v1.9.0
			os << "[" << nghttp2_http2_strerror(error_code) << "]";
#endif
			os << endl;
			break;
		}
		case NGHTTP2_SETTINGS:
			os << endl;
			if (frame.settings.niv > 0) {
				for (unsigned i = 0; i < frame.settings.niv; ++i) {
					const auto &iv = frame.settings.iv[i];
					os << iv.settings_id << " : " << iv.value << endl;
				}
			} else {
				os << "<empty>" << endl;
			}
			break;
		case NGHTTP2_GOAWAY:
			os << "lastStreamId: " << frame.goaway.last_stream_id << endl;
			os << "errorCode: " << frame.goaway.error_code << endl;
			os << endl;
			if (frame.goaway.opaque_data) {
				os.write(reinterpret_cast<char *>(frame.goaway.opaque_data), frame.goaway.opaque_data_len);
				os << endl;
			} else {
				os << "<empty>" << endl;
			}
			break;
		default:
			break;
	};
	return os;
}
