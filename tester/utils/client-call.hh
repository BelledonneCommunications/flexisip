/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <functional>
#include <memory>

#include <linphone++/call.hh>
#include <linphone++/call_listener.hh>
#include <linphone++/enums.hh>
#include <ortp/rtp.h>
#include <ortp/rtpsession.h>

namespace flexisip {
namespace tester {

class ClientCall {
public:
	ClientCall(std::shared_ptr<linphone::Call>&&);

	const ::rtp_stats& getVideoRtpStats() const;
	const ::RtpTransport& getMetaRtpTransport() const;
	const ::RtpSession* getRtpSession() const;
	linphone::Status accept() const;
	linphone::Status acceptEarlyMedia() const;
	linphone::Status decline(linphone::Reason) const;
	linphone::Status terminate() const;
	linphone::Call::State getState() const;
	linphone::Reason getReason() const;
	linphone::MediaDirection getAudioDirection() const;
	std::shared_ptr<const linphone::Address> getRemoteAddress() const;
	const bool& videoFrameDecoded();

	linphone::Status
	    update(std::function<std::shared_ptr<linphone::CallParams>(std::shared_ptr<linphone::CallParams>&&)>) const;

	void setStaticPictureFps(float fps);

	/* CHEATS ~~ Use only for quick prototyping */
	static const std::shared_ptr<linphone::Call>& getLinphoneCall(const ClientCall&);

private:
	class VideoDecodedListener : public linphone::CallListener {
	public:
		bool mFrameDecoded = false;

	private:
		void onNextVideoFrameDecoded(const std::shared_ptr<linphone::Call>&) override {
			mFrameDecoded = true;
		}
	};

	std::shared_ptr<linphone::Call> mCall;
	std::shared_ptr<VideoDecodedListener> mListener{nullptr};
};

} // namespace tester
} // namespace flexisip
