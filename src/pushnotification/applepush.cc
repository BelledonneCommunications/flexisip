
#include "applepush.hh"
#include <flexisip/common.hh>
#include <sstream>
#include <string>
#include <stdexcept>

using namespace std;

namespace flexisip {
namespace pushnotification {

uint32_t AppleRequest::sIdentifier = 1;

AppleRequest::AppleRequest(const PushInfo &info) : Request(info.mAppId, "apple") {
	const string &deviceToken = info.mDeviceToken;
	const string &msg_id = info.mAlertMsgId;
	const string &arg = info.mFromName.empty() ? info.mFromUri : info.mFromName;
	const string &sound = info.mAlertSound;
	const string &callid = info.mCallId;
	string date = getPushTimeStamp();

	const char *rawPayload;
	size_t bufferMaxSize = MAXPAYLOAD_SIZE + 1;
	char buffer[bufferMaxSize];
	int returnCode = 0;

	int ret = formatDeviceToken(deviceToken);
	if ((ret != 0) || (mDeviceToken.size() != DEVICE_BINARY_SIZE)) {
		throw runtime_error("ApplePushNotification: Invalid deviceToken");
	}
	mTtl = info.mTtl;

	switch (info.mApplePushType) {
		case PushInfo::ApplePushType::Pushkit:
		// We also need msg_id and callid in case the push is received but the device cannot register
		rawPayload = R"json({
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
		returnCode = snprintf(buffer, bufferMaxSize, rawPayload,
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
	case PushInfo::ApplePushType::Background:
		// Use a normal push notification with content-available set to 1, no alert, no sound.
		rawPayload = R"json({
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
		returnCode = snprintf(buffer, bufferMaxSize, rawPayload,
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
	case PushInfo::ApplePushType::RemoteBasic:
		/* some apps don't want the push to update the badge - but if they do,
		we always put the badge value to 1 because we want to notify the user that
		he/she has unread messages even if we do not know the exact count */
		rawPayload = R"json({
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
		returnCode = snprintf(buffer, bufferMaxSize, rawPayload,
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
	case PushInfo::ApplePushType::RemoteWithMutableContent:
		/* some apps don't want the push to update the badge - but if they do,
		we always put the badge value to 1 because we want to notify the user that
		he/she has unread messages even if we do not know the exact count */
		rawPayload = R"json({
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
		returnCode = snprintf(buffer, bufferMaxSize, rawPayload,
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

	mPayload = buffer;
	SLOGD << "PNR " << this << " payload is " << mPayload;
	if (returnCode < 0 || returnCode >= (int)bufferMaxSize) {
		SLOGE << "PNR " << this << " cannot be sent because the payload size is higher than " << MAXPAYLOAD_SIZE;
		mPayload.clear();
		return;
	}
}

int AppleRequest::formatDeviceToken(const string &deviceToken) {
	char car = 0;
	char oct = 0;
	char val;

	mDeviceToken.clear();
	for (unsigned int i = 0; i < deviceToken.length(); ++i) {
		char tokenCar = deviceToken[i];
		if (tokenCar >= '0' && tokenCar <= '9') {
			val = tokenCar - '0';
		} else if (tokenCar >= 'a' && tokenCar <= 'f') {
			val = tokenCar - 'a' + 10;
		} else if (tokenCar >= 'A' && tokenCar <= 'F') {
			val = tokenCar - 'A' + 10;
		} else if (tokenCar == ' ' || tokenCar == '\t') {
			continue;
		} else {
			return -1;
		}
		if (oct) {
			car |= val & 0x0f;
		} else {
			car = val << 4;
		}
		oct = 1 - oct;
		if (oct == 0) {
			mDeviceToken.push_back(car);
		}
	}
	return 0;
}

std::string AppleRequest::getDeviceTokenAsString() const noexcept {
	ostringstream token{};
	token << hex;
	for (const auto &byte : mDeviceToken) {
		token << byte;
	}
	return token.str();
}

std::size_t AppleRequest::writeItem(std::size_t pos, const Item& item)
{
	size_t newSize = pos + sizeof(uint8_t) + sizeof(uint16_t) + item.mData.size();
	uint16_t itemSize = htons((uint16_t)item.mData.size());
	if (mBuffer.size()<newSize){
		mBuffer.resize(newSize);
	}
	mBuffer[pos] = item.mId;
	pos++;
	memcpy(&mBuffer[pos], &itemSize, sizeof(uint16_t));
	pos += sizeof(uint16_t);
	memcpy(&mBuffer[pos], &item.mData[0], item.mData.size());
	pos += item.mData.size();
	return pos;
}

const vector<char> &AppleRequest::getData() {
	size_t pos = 0;
	uint32_t frameSize;
	/* Init */
	mBuffer.clear();
	mBuffer.resize(sizeof(uint8_t) + sizeof(frameSize));

	mBuffer[pos] = 2;
	pos += sizeof(uint8_t);
	//the frame size will be written at the end of the processing
	pos += sizeof(frameSize);

	//now write items

	//device token item:
	Item item;
	item.mId = 1;
	item.mData = mDeviceToken;
	pos = writeItem(pos, item);

	//payload item:
	item.clear();
	item.mId = 2;
	item.mData.assign(mPayload.begin(), mPayload.end());
	pos = writeItem(pos, item);

	//Notification identifier
	item.clear();
	item.mId = 3;
	item.mData.resize(sizeof(sIdentifier));
	memcpy(&item.mData[0], &sIdentifier, sizeof(sIdentifier));
	pos = writeItem(pos, item);

	//Expiration date item
	item.clear();
	item.mId = 4;
	uint32_t expires = htonl((uint32_t)(time(NULL) + mTtl));
	item.mData.resize(sizeof(expires));
	memcpy(&item.mData[0], &expires, sizeof(expires));
	pos = writeItem(pos, item);

	//Priority item
	item.clear();
	item.mId = 5;
	uint8_t priority = 10; //top priority
	item.mData.push_back(priority);
	pos = writeItem(pos, item);

	//now write the total length of items for this frame
	frameSize = pos - sizeof(uint8_t) - sizeof(frameSize);
	frameSize = htonl(frameSize);
	memcpy(&mBuffer[1], &frameSize, sizeof(frameSize));

	return mBuffer;
}

string AppleRequest::isValidResponse(const string &str) {
	// error response is COMMAND(1)|STATUS(1)|ID(4) in bytes
	if (str.length() >= 6) {
		uint8_t error = str[1];
		uint32_t identifier = (uint32_t)str[2];
		static const char* errorToString[] = {
			"No errors encountered",
			"Processing error",
			"Missing device token",
			"Missing topic",
			"Missing payload",
			"Invalid token size",
			"Invalid topic size",
			"Invalid payload size",
			"Invalid token",
		};
		stringstream ss;
		ss << "PNR " << this << " with identifier " << identifier << " failed with error "
		<< (int)error << " (" << (error>8 ? "unknown" : errorToString[error]) << ")";
		return ss.str();
	}
	return "";
}

AppleClient::DataProvider::DataProvider(const std::vector<char> &data) noexcept {
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

bool AppleClient::sendPush(const std::shared_ptr<Request> &req) {
	auto appleReq = dynamic_pointer_cast<AppleRequest>(req);

	if (!isConnected()) connect();

	constexpr auto methodLabel = ":method";
	constexpr auto method = "POST";
	constexpr auto pathLabel = ":path";
	auto path = string{"/3/device/"} + appleReq->getDeviceTokenAsString();
	nghttp2_nv headers[2] = {
		{(uint8_t *)methodLabel, (uint8_t *)method, strlen(methodLabel), strlen(method), NGHTTP2_NV_FLAG_NONE},
		{(uint8_t *)pathLabel, (uint8_t *)path.c_str(), strlen(methodLabel), path.size(), NGHTTP2_NV_FLAG_NONE}
	};

	DataProvider dataProv{req->getData()};
	auto status = nghttp2_submit_request(mHttpSession.get(), nullptr, headers, sizeof(headers), dataProv.getCStruct(), nullptr);
	if (status < 0) {
		SLOGE << "Http2Transport: push request submit failed. reason=[" << nghttp2_strerror(status) << "]";
		return false;
	}
	status = nghttp2_session_send(mHttpSession.get());
	if (status < 0) {
		SLOGE << "Http2Transport: push request sending failed. reason=[" << nghttp2_strerror(status) << "]";
		return false;
	}
	return 0;
}

void AppleClient::connect() {
	if (isConnected()) return;
	mConn->connect();

	auto sendCb = [](nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) noexcept {
		auto thiz = static_cast<AppleClient *>(user_data);
		return thiz->send(data, length);
	};
	auto recvCb = [](nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data) noexcept {
		auto thiz = static_cast<AppleClient *>(user_data);
		return thiz->recv(buf, length);
	};
	auto frameSentCb = [](nghttp2_session *session, const nghttp2_frame *frame, void *user_data) noexcept {
		auto thiz = static_cast<AppleClient *>(user_data);
		thiz->onFrameSent(frame);
		return 0;
	};
	auto frameRecvCb = [](nghttp2_session *session, const nghttp2_frame *frame, void *user_data) noexcept {
		auto thiz = static_cast<AppleClient *>(user_data);
		thiz->onFrameRecv(frame);
		return 0;
	};
	auto onDataChunkRecvCb = [](nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data) noexcept {
		auto thiz = static_cast<AppleClient *>(user_data);
		thiz->onDataReceived(stream_id, data, len);
		return 0;
	};

	nghttp2_session_callbacks *cbs;
	nghttp2_session_callbacks_new(&cbs);
	nghttp2_session_callbacks_set_send_callback(cbs, sendCb);
	nghttp2_session_callbacks_set_recv_callback(cbs, recvCb);
	nghttp2_session_callbacks_set_on_frame_send_callback(cbs, frameSentCb);
	nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, frameRecvCb);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, onDataChunkRecvCb);

	nghttp2_session *session;
	nghttp2_session_client_new(&session, cbs, this);
	mHttpSession.reset(session);

	su_wait_create(&mPollInWait, mConn->getFd(), SU_WAIT_IN);
	su_root_register(mRoot, &mPollInWait, onPollInCb, this, su_pri_normal);

	nghttp2_session_callbacks_del(cbs);
}

void AppleClient::disconnect() {
	if (!isConnected()) return;
	su_root_unregister(mRoot, &mPollInWait, onPollInCb, this);
	mHttpSession.reset();
	mConn->disconnect();
}

ssize_t AppleClient::send(const uint8_t *data, size_t length) noexcept {
	length = min(length, size_t(numeric_limits<int>::max()));
	auto nwritten = mConn->write(data, int(length));
	if (nwritten < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
	if (nwritten == 0) return NGHTTP2_ERR_WOULDBLOCK;
	return nwritten;
}

ssize_t AppleClient::recv(uint8_t *data, size_t length) noexcept {
	length = min(length, size_t(numeric_limits<int>::max()));
	auto nread = mConn->read(data, length);
	if (nread < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
	if (nread == 0) return NGHTTP2_ERR_WOULDBLOCK;
	return nread;
}

void AppleClient::onFrameSent(const nghttp2_frame *frame) noexcept {
	SLOGD << "AppleClient: HTTP2 frame sent (streamId=" << frame->hd.stream_id
		<< ", type=" << frameTypeToString(frame->hd.type) << ")";
}

void AppleClient::onFrameRecv(const nghttp2_frame *frame) noexcept {
	ostringstream msg{};
	msg << "AppleClient: HTTP2 frame received (streamId=" << frame->hd.stream_id
		<< ", type=" << frameTypeToString(frame->hd.type) << ")";
	if (frame->hd.type == NGHTTP2_GOAWAY && frame->goaway.opaque_data) {
		msg << ":\n";
		msg.write(reinterpret_cast<char *>(frame->goaway.opaque_data), frame->goaway.opaque_data_len);
	}
	SLOGD << msg.str();
	if (frame->hd.type == NGHTTP2_GOAWAY) {
		disconnect();
	}
}

void AppleClient::onDataReceived(int32_t streamId, const uint8_t *data, size_t datalen) noexcept {
	ostringstream msg{};
	msg << "AppleClient: " << datalen << "B of data received on stream[" << streamId << "]:\n";
	msg.write(reinterpret_cast<const char *>(data), datalen);
	SLOGD << msg.str();
}

int AppleClient::onPollInCb(su_root_magic_t *, su_wait_t *, su_wakeup_arg_t *arg) noexcept {
	auto thiz = static_cast<AppleClient *>(arg);
	auto status = nghttp2_session_recv(thiz->mHttpSession.get());
	if (status == NGHTTP2_ERR_EOF) {
		SLOGD << "AppleClient: connection closed by remote. Disconnecting";
		thiz->disconnect();
	}
	if (status < 0) {
		SLOGD << "AppleClient: error while receiving HTTP2 data. Disconnecting";
		thiz->disconnect();
	}
	return 0;
}

const char *AppleClient::frameTypeToString(uint8_t frameType) noexcept {
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
		case NGHTTP2_ALTSVC:        return "ALTSVC";
		case NGHTTP2_ORIGIN:        return "ORIGIN";
	}
	return "UNKNOWN";
}

} // end of pushnotification namespace
} // end of flexisip namespace
