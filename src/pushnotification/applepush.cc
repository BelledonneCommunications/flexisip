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
#include <iomanip>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>

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

	if (info.mTtl > 0) {
		mExpire = time(nullptr) + info.mTtl;
	}

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
				"pn_ttl": %d
			})json";
			nwritten = snprintf(mPayload.data(), mPayload.size(), rawPayload,
				msg_id.c_str(),
				arg.c_str(),
				callid.c_str(),
				quoteStringIfNeeded(info.mUid).c_str(),
				date.c_str(),
				info.mFromUri.c_str(),
				info.mFromName.c_str(),
				info.mTtl
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
				"pn_ttl": %d
			})json";
			nwritten = snprintf(mPayload.data(), mPayload.size(), rawPayload,
				msg_id.c_str(),
				arg.c_str(),
				callid.c_str(),
				quoteStringIfNeeded(info.mUid).c_str(),
				date.c_str(),
				info.mFromUri.c_str(),
				info.mFromName.c_str(),
				info.mTtl
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
				"send-time": "%s"
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
				date.c_str()
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
				"chat-room-addr": "%s"
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
				info.mChatRoomAddr.c_str()
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

std::string AppleClient::BadStateError::formatWhatArg(State state) noexcept {
	return string{"bad state ["} + to_string(unsigned(state)) + "]";
}

void AppleClient::HeaderStore::add(std::string name, std::string value, uint8_t flags) noexcept {
	auto it = find_if(mHList.begin(), mHList.end(), [&name](const Header &h){return h.name == name;});
	if (it == mHList.end()) {
		it = mHList.emplace(mHList.end());
	}
	it->name = move(name);
	it->value = move(value);
	it->flags = flags;
}

std::string AppleClient::HeaderStore::toString() const noexcept {
	ostringstream os{};
	for (const auto &h : mHList) {
		os << h.name << " = " << h.value << endl;
	}
	return os.str();
}

std::vector<nghttp2_nv> AppleClient::HeaderStore::makeHeaderList() const noexcept {
	CHeaderList cHList{};
	cHList.reserve(mHList.size());
	for (const auto &header : mHList) {
		cHList.emplace_back(
			nghttp2_nv{
				(uint8_t *)header.name.c_str(),
				(uint8_t *)header.value.c_str(),
				header.name.size(),
				header.value.size(),
				header.flags
			}
		);
	}
	return cHList;
}

AppleClient::DataProvider::DataProvider(const std::vector<char> &data) noexcept {
	mDataProv.source.ptr = this;
	mDataProv.read_callback = [](nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
							  uint32_t *data_flags, nghttp2_data_source *source, void *user_data) noexcept {
		return static_cast<DataProvider *>(source->ptr)->read(buf, length, data_flags);
	};
	mData.write(data.data(), data.size());
}

AppleClient::DataProvider::DataProvider(const std::string &data) noexcept {
	mDataProv.source.ptr = this;
	mDataProv.read_callback = [](nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
							  uint32_t *data_flags, nghttp2_data_source *source, void *user_data) noexcept {
		return static_cast<DataProvider *>(source->ptr)->read(buf, length, data_flags);
	};
	mData.write(data.data(), data.size());
}

ssize_t AppleClient::DataProvider::read(uint8_t *buf, size_t length, uint32_t *data_flags) noexcept {
	*data_flags = 0;
	mData.read(reinterpret_cast<char *>(buf), length);
	if (mData.eof()) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
	if (!mData.good() && !mData.eof()) return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
	return mData.gcount();
}

AppleClient::PnrContext::PnrContext(AppleClient &client, const std::shared_ptr<AppleRequest> &pnr, unsigned timeout /* s */) noexcept
	: mPnr{pnr} {
	mTimer = make_unique<sofiasip::Timer>(&client.mRoot, timeout * 1000);

	/* WARNING: the lambda function which is called by the time captures the *this* pointer
	 * of the PnrContext. So, ensure that PnrContext is neither copy/move constructible not copy/move assignable. */
	mTimer->set([&client, this] () {
		SLOGE << client.mLogPrefix << ": request timeout.";
		mPnr->setState(Request::State::Failed);
		auto &pnrToRemove = mPnr;
		auto it = find_if(
			client.mPNRs.begin(), client.mPNRs.end(),
			[&pnrToRemove](const auto &e){return e.second->mPnr == pnrToRemove;}
		);
		client.mPNRs.erase(it);
	});
}

AppleClient::AppleClient(su_root_t &root, std::unique_ptr<TlsConnection> &&conn)
	: mRoot{root}, mIdleTimer{&root, sIdleTimeout * 1000}, mConn{std::move(conn)} {
	ostringstream os{};
	os << "AppleClient[" << this << "]";
	mLogPrefix = os.str();
	SLOGD << mLogPrefix << ": constructing AppleClient with TlsConnection[" << mConn.get() << "]";
}

bool AppleClient::sendPush(const std::shared_ptr<Request> &req) {
	auto appleReq = dynamic_pointer_cast<AppleRequest>(req);
	mPendingPNRs.emplace(move(appleReq));

	if (mState != State::Connected) {
		if (mState == State::Disconnected) connect();
		return true;
	}

	return sendAllPendingPNRs();
}

void AppleClient::connect() {
	if (mState != State::Disconnected) {
		throw BadStateError(mState);
	}
	setState(State::Connecting);

	try {
		mConn->connect();
		if (!mConn->isConnected()) throw runtime_error{"TLS connection failed"};

		auto sendCb = [](nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) noexcept {
			auto thiz = static_cast<AppleClient *>(user_data);
			return thiz->send(*session, data, length);
		};
		auto recvCb = [](nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data) noexcept {
			auto thiz = static_cast<AppleClient *>(user_data);
			return thiz->recv(*session, buf, length);
		};
		auto frameSentCb = [](nghttp2_session *session, const nghttp2_frame *frame, void *user_data) noexcept {
			auto thiz = static_cast<AppleClient *>(user_data);
			thiz->onFrameSent(*session, *frame);
			return 0;
		};
		auto frameRecvCb = [](nghttp2_session *session, const nghttp2_frame *frame, void *user_data) noexcept {
			auto thiz = static_cast<AppleClient *>(user_data);
			thiz->onFrameRecv(*session, *frame);
			return 0;
		};
		auto onHeaderRecvCb = [](nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
								const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data) noexcept {
			auto thiz = static_cast<AppleClient *>(user_data);
			string nameStr{reinterpret_cast<const char *>(name), namelen};
			string valueStr{reinterpret_cast<const char *>(value), valuelen};
			thiz->onHeaderRecv(*session, *frame, nameStr, valueStr, flags);
			return 0;
		};
		auto onDataChunkRecvCb = [](nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data) noexcept {
			auto thiz = static_cast<AppleClient *>(user_data);
			thiz->onDataReceived(*session, flags, stream_id, data, len);
			return 0;
		};
		auto onStreamClosedCb = [](nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) noexcept {
			auto thiz = static_cast<AppleClient *>(user_data);
			thiz->onStreamClosed(*session, stream_id, error_code);
			return 0;
		};

		nghttp2_session_callbacks *cbs;
		nghttp2_session_callbacks_new(&cbs);
		nghttp2_session_callbacks_set_send_callback(cbs, sendCb);
		nghttp2_session_callbacks_set_recv_callback(cbs, recvCb);
		nghttp2_session_callbacks_set_on_frame_send_callback(cbs, frameSentCb);
		nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, frameRecvCb);
		nghttp2_session_callbacks_set_on_header_callback(cbs, onHeaderRecvCb);
		nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, onDataChunkRecvCb);
		nghttp2_session_callbacks_set_on_stream_close_callback(cbs, onStreamClosedCb);;

		unique_ptr<nghttp2_session_callbacks, void(*)(nghttp2_session_callbacks *)> cbsPtr{cbs, nghttp2_session_callbacks_del};

		nghttp2_session *session;
		nghttp2_session_client_new(&session, cbs, this);
		NgHttp2SessionPtr httpSession{session};

		int status;
		if ((status = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0)) < 0) {
			throw runtime_error{"submitting settings failed [status=" + to_string(status) + "]"};
		}
		if ((status = nghttp2_session_send(session)) < 0) {
			throw runtime_error{"sending SETTINGS frame failed [status=" + to_string(status) + "]"};
		}

		mHttpSession = move(httpSession);
		su_wait_create(&mPollInWait, mConn->getFd(), SU_WAIT_IN);
		su_root_register(&mRoot, &mPollInWait, onPollInCb, this, su_pri_normal);

		resetIdleTimer();

	} catch (const runtime_error &e) {
		SLOGE << mLogPrefix << ": " << e.what();
		disconnect();
	}
}

void AppleClient::disconnect() {
	SLOGD << mLogPrefix << ": disconnecting from APNS";
	if (mState == State::Disconnected) return;
	su_root_unregister(&mRoot, &mPollInWait, onPollInCb, this);
	mHttpSession.reset();
	mConn->disconnect();
	setState(State::Disconnected);
	mLastSID = -1;
	mPNRs.clear();
}

bool AppleClient::sendAllPendingPNRs() {
	auto pnrSent = false;
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
		hStore.add( ":method"         , "POST"                                         );
		hStore.add( ":scheme"         , "https"                                        );
		hStore.add( ":path"           , move(path)                                     );
		hStore.add( "host"            , move(host)                                     );
		hStore.add( "apns-expiration" , to_string(appleReq->mExpire)                   );
		hStore.add( "apns-topic"      , apnsTopic                                      );
		hStore.add( "apns-push-type"  , pushTypeToApnsPushType(appleReq->mPayloadType) );
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

		mPNRs.emplace(streamId, make_unique<PnrContext>(*this, appleReq, sPnrTimeout));
		appleReq->setState(Request::State::InProgress);

		pnrSent = true;
	}

	if (pnrSent) resetIdleTimer();
	return true;
}

void AppleClient::processGoAway() {
	SLOGD << mLogPrefix << ": closing connection after receiving GOAWAY frame. Last processed stream is [" << mLastSID << "]";

	// move back all the non-treated PNRs into the pending queue
	for (auto it = mPNRs.begin(); it != mPNRs.end(); it = mPNRs.erase(it)) {
		const auto &sid = it->first;
		auto &request = it->second->getPnr();
		if (sid > mLastSID) {
			SLOGD << mLogPrefix << ": PNR " << request  << " will be sent on next connection";
			request->setState(Request::State::NotSubmitted);
			mPendingPNRs.emplace(move(request));
		}
	}

	// disconnect and connect again if there still are PNRs to process
	disconnect();
	if (!mPendingPNRs.empty()) {
		SLOGD << mLogPrefix << ": PNRs are waiting. Connecting to server again";
		connect();
	}
}

void AppleClient::setState(State state) noexcept {
	if (mState == state) return;
	SLOGD << mLogPrefix << ": switching state from [" << mState << "] to [" << state << "]";
	mState = state;
}

ssize_t AppleClient::send(nghttp2_session &session, const uint8_t *data, size_t length) noexcept {
	length = min(length, size_t(numeric_limits<int>::max()));
	auto nwritten = mConn->write(data, int(length));
	if (nwritten < 0) {
		SLOGE << mLogPrefix << ": error while writting into socket[" << nwritten << "]";
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	if (nwritten == 0 && length > 0) return NGHTTP2_ERR_WOULDBLOCK;
	return nwritten;
}

ssize_t AppleClient::recv(nghttp2_session &session, uint8_t *data, size_t length) noexcept {
	length = min(length, size_t(numeric_limits<int>::max()));
	auto nread = mConn->read(data, length, 0ms);
	if (nread < 0) {
		SLOGE << mLogPrefix << ": error while reading socket. " << strerror(errno);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	if (nread == 0 && length > 0) return NGHTTP2_ERR_WOULDBLOCK;
	return nread;
}

void AppleClient::onFrameSent(nghttp2_session &session, const nghttp2_frame &frame) noexcept {
// 	SLOGD << mLogPrefix << "[" << frame.hd.stream_id << "]: frame sent (" << frame.hd.length << "B):\n" << frame;
}

void AppleClient::onFrameRecv(nghttp2_session &session, const nghttp2_frame &frame) noexcept {
// 	SLOGD << mLogPrefix << "[" << frame.hd.stream_id << "]: frame received (" << frame.hd.length << "B):\n" << frame;
	switch (frame.hd.type) {
		case NGHTTP2_SETTINGS:
			if (mState == State::Connecting && (frame.hd.flags & NGHTTP2_FLAG_ACK) == 0) {
				SLOGD << mLogPrefix << ": server settings received";
				setState(State::Connected);
				SLOGD << mLogPrefix << ": sending all pending PNRs";
				sendAllPendingPNRs();
			}
			break;
		case NGHTTP2_GOAWAY: {
			ostringstream msg{};
			msg << mLogPrefix << ": GOAWAY frame received, errorCode=[" << frame.goaway.error_code << "], lastStreamId=["
				<< frame.goaway.last_stream_id << "]:";
			if (frame.goaway.opaque_data_len > 0) {
				msg << endl;
				msg.write(reinterpret_cast<const char *>(frame.goaway.opaque_data), frame.goaway.opaque_data_len);
			} else {
				msg << " <empty>";
			}
			SLOGD << msg.str();
			SLOGD << "Scheduling connection closing";
			mLastSID = frame.goaway.last_stream_id;
			break;
		}
	}
}

void AppleClient::onHeaderRecv(nghttp2_session &session, const nghttp2_frame &frame, const std::string &name,
					           const std::string &value, uint8_t flags) noexcept {
	const auto &streamId = frame.hd.stream_id;
	auto logPrefix = string{mLogPrefix} + "[" + to_string(streamId) + "]";
	SLOGD << logPrefix << ": receiving HTTP2 header [" << name << " = " << value << "]";
	if (name == ":status") {
		AppleRequest *pnr = nullptr;
		try {
			pnr = mPNRs.at(streamId)->getPnr().get();
		} catch (const logic_error &) {
			SLOGE << logPrefix << ": receiving header for an unknown stream. Just ignoring";
			return;
		}
		try {
			pnr->mStatusCode = stoi(value);
		} catch (const logic_error &e) {
			SLOGE << logPrefix << ": error while parsing status code[" << value << "]: " << e.what();
			return;
		}
		if (pnr->mStatusCode == 200) {
			pnr->setState(Request::State::Successful);
			SLOGD << logPrefix << ": PNR " << pnr << " succeeded";
		} else {
			pnr->setState(Request::State::Failed);
			SLOGD << logPrefix << ": PNR " << pnr << " failed";
		}
	}
}

void AppleClient::onDataReceived(nghttp2_session &session, uint8_t flags, int32_t streamId, const uint8_t *data, size_t datalen) noexcept {
	ostringstream msg{};
	msg << mLogPrefix << "[" << streamId << "]";
	msg << ": " << datalen << "B of data received on stream[" << streamId << "]:\n";
	msg.write(reinterpret_cast<const char *>(data), datalen);
	SLOGD << msg.str();
}

int AppleClient::onPollInCb(su_root_magic_t *, su_wait_t *, su_wakeup_arg_t *arg) noexcept {
	auto thiz = static_cast<AppleClient *>(arg);
	auto status = nghttp2_session_recv(thiz->mHttpSession.get());
	if (status < 0) {
		SLOGE << thiz->mLogPrefix << ": error while receiving HTTP2 data[" << nghttp2_strerror(status) << "]. Disconnecting";
		thiz->disconnect();
		return 0;
	}
	if (thiz->mLastSID >= 0) thiz->processGoAway();
	return 0;
}

void AppleClient::onStreamClosed(nghttp2_session &session, int32_t stream_id, uint32_t error_code) noexcept {
	auto logPrefix = mLogPrefix + "[" + to_string(stream_id) + "]";
	SLOGD << logPrefix << ": stream closed with error code [" << error_code << "]";
	auto it = mPNRs.find(stream_id);
	if (it != mPNRs.cend()) {
		SLOGD << logPrefix << ": end of PNR " << it->second->getPnr();
		mPNRs.erase(it);
	}
}

void AppleClient::onConnectionIdle() noexcept {
	SLOGD << mLogPrefix << ": connection is idle";
	disconnect();
}

std::string AppleClient::pushTypeToApnsPushType(ApplePushType type) {
	string res{};
	switch (type) {
		case ApplePushType::Unknown:
			throw invalid_argument("no 'apns-push-type' value for 'ApplePushType::Unknown'");
		case ApplePushType::RemoteBasic:
		case ApplePushType::RemoteWithMutableContent:
			res = "alert";
			break;
		case ApplePushType::Background:
			res = "background";
			break;
		case ApplePushType::Pushkit:
			res = "voip";
			break;
	}
	return res;
}

constexpr unsigned AppleClient::sPnrTimeout;
constexpr unsigned AppleClient::sIdleTimeout;

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

std::ostream &operator<<(std::ostream &os, flexisip::pushnotification::AppleClient::State state) noexcept {
	switch (state) {
		case AppleClient::State::Disconnected: return os << "Disconnected";
		case AppleClient::State::Connecting: return os << "Connecting";
		case AppleClient::State::Connected: return os << "Connected";
	};
	return os << "Unknown";
}
