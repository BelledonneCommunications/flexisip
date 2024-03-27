/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "client-call.hh"

#include <memory>

#include "linphone++/call_params.hh"
#include "linphone++/core.hh"
#include "linphone++/enums.hh"
#include "linphone/api/c-call-stats.h"
#include "linphone/api/c-call.h"
#include "ortp/rtp.h"

namespace flexisip {
namespace tester {

ClientCall::ClientCall(std::shared_ptr<linphone::Call>&& call) : mCall(std::move(call)) {
}

const ::rtp_stats& ClientCall::getVideoRtpStats() const {
	return *::linphone_call_stats_get_rtp_stats(::linphone_call_get_video_stats(mCall->cPtr()));
}

linphone::Status ClientCall::accept() const {
	return mCall->accept();
}
linphone::Status ClientCall::acceptEarlyMedia() const {
	return mCall->acceptEarlyMedia();
}
linphone::Status ClientCall::decline(linphone::Reason reason) const {
	return mCall->decline(reason);
}
linphone::Status ClientCall::terminate() const {
	return mCall->terminate();
}

linphone::Call::State ClientCall::getState() const {
	return mCall->getState();
}
linphone::Reason ClientCall::getReason() const {
	return mCall->getReason();
}
linphone::MediaDirection ClientCall::getAudioDirection() const {
	return mCall->getCurrentParams()->getAudioDirection();
}
std::shared_ptr<const linphone::Address> ClientCall::getRemoteAddress() const {
	return mCall->getRemoteAddress();
}

const bool& ClientCall::videoFrameDecoded() {
	if (mListener) {
		mListener->mFrameDecoded = false;
		mCall->requestNotifyNextVideoFrameDecoded();
	} else {
		mListener = std::make_shared<VideoDecodedListener>();
		mCall->addListener(mListener);
	}
	return mListener->mFrameDecoded;
}

linphone::Status ClientCall::update(
    std::function<std::shared_ptr<linphone::CallParams>(std::shared_ptr<linphone::CallParams>&&)> tweak) const {
	return mCall->update(tweak(mCall->getCore()->createCallParams(mCall)));
}

const std::shared_ptr<linphone::Call>& ClientCall::getLinphoneCall(const ClientCall& wrapper) {
	return wrapper.mCall;
}

} // namespace tester
} // namespace flexisip
