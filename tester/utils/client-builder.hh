/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <variant>

#include "agent.hh"
#include "flexisip/flexisip-version.h"
#include "linphone++/linphone.hh"
#include "tester.hh"

namespace flexisip {

namespace pushnotification {

class RFC8599PushParams;

}

namespace tester {

namespace port {

struct Auto {};

struct Port {
	std::uint16_t port;
};

struct Range {
	std::uint16_t min;
	std::uint16_t max;
};

using PortSetting = std::variant<Auto, Port, Range>;

} // namespace port

class CoreClient;

enum class OnOff : bool {
	Off = false,
	On = true,
};

enum class AudioCodec : std::uint8_t {
	// Don't force anything
	AllSupported,
	Speex8000HzMono,
	PCMU8000HzMono,
};

class ClientBuilder {
public:
	explicit ClientBuilder(const std::shared_ptr<Agent>&);
	explicit ClientBuilder(const std::string&);

	ClientBuilder(ClientBuilder&&) = default;
	// We don't want to share e.g. AccountParams between builders
	ClientBuilder(const ClientBuilder&) = delete;

	void setLimeX3DH(OnOff);
	/**
	 * Whether the client will send video data in video calls
	 */
	ClientBuilder& setVideoSend(OnOff);
	/**
	 * Whether the client will decode video data in video calls
	 */
	ClientBuilder& setVideoReceive(OnOff);
	ClientBuilder& setRtcpSend(OnOff);
	ClientBuilder& setIce(OnOff);
	ClientBuilder& setCpimInBasicChatroom(OnOff);
	ClientBuilder& setRegistration(OnOff);
	ClientBuilder& setConferenceFactoryAddress(const std::shared_ptr<linphone::Address>& address);
	ClientBuilder& setCustomContact(const std::string& contact);
	ClientBuilder& setPushParams(const pushnotification::RFC8599PushParams& params);
	ClientBuilder& setInactiveAudioOnPause(OnOff);
	ClientBuilder& setAudioPort(port::PortSetting);
	ClientBuilder& setVideoPort(port::PortSetting);

	/**
	 * Add some Apple-specific push info to REGISTERs
	 */
	ClientBuilder& setApplePushConfig();
	ClientBuilder& setApplePushConfigRemoteOnly();
	ClientBuilder& setPassword(const std::string_view& password);
	ClientBuilder& setAudioOutputFilePath(const std::filesystem::path&);
	ClientBuilder& setAudioInputFilePath(const std::filesystem::path&);
	/**
	 * Force audio codec
	 */
	ClientBuilder& setAudioCodec(AudioCodec);

	ClientBuilder& setMwiServerAddress(const std::shared_ptr<linphone::Address>& address);
	ClientBuilder& setAutoAnswerReplacingCalls(OnOff);
	/** Set a different expiration time for messages. Lets contacts linger in the RegistrarDB beyond the standard
	 * expiration time to keep receiving MESSAGEs. Any other type of SIP request will trigger a 404 as if the contact
	 * were expired.
	 */
	ClientBuilder& setMessageExpires(std::chrono::seconds delay);
	ClientBuilder& setUserAgent(const std::string& userAgent, const std::string& version = FLEXISIP_GIT_VERSION);

	CoreClient build(const std::string&) const;
	std::shared_ptr<CoreClient> make(const std::string&) const;

private:
	const std::shared_ptr<linphone::Factory> mFactory{linphone::Factory::get()};
	const std::shared_ptr<linphone::Core> mCoreTemplate{};
	const std::shared_ptr<linphone::AccountParams> mAccountParams{};
	const std::shared_ptr<Agent> mAgent;
	OnOff mLimeX3DH{OnOff::On};
	OnOff mSendVideo{OnOff::Off};
	OnOff mReceiveVideo{OnOff::Off};
	OnOff mSendRtcp{OnOff::On};
	OnOff mIce{OnOff::Off};
	OnOff mRegister{OnOff::On};
	OnOff mSetAudioInactiveOnPause{OnOff::Off};
	OnOff mAutoAnswerReplacingCalls{OnOff::On};
	AudioCodec mAudioCodec = AudioCodec::AllSupported;
	port::PortSetting mAudioPort = port::Auto();
	port::PortSetting mVideoPort = port::Auto();
	std::string mPassword{};
	std::string mRecordFilePath{};
	// Final checks on call successfully established is based on bandwidth usage.
	// Use this file as input to make sure there is always some traffic.
	std::string mPlayFilePath{bcTesterRes("sounds/hello8000.wav")};
	std::string mUserAgentName{"Linphone (Flexisip tester)"};
	std::string mUserAgentVersion{FLEXISIP_GIT_VERSION};
	std::string mRemoteAddress{};
};

} // namespace tester
} // namespace flexisip