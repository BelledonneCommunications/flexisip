/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "agent.hh"
#include <linphone++/linphone.hh>

namespace flexisip {
namespace pushnotification {

class RFC8599PushParams;

}
namespace tester {

class CoreClient;

enum class OnOff : bool {
	Off = 0,
	On = 1,
};

enum class AudioCodec : std::uint8_t {
	// Don't force anything
	AllSupported,
	Speex8000HzMono,
	PCMU8000HzMono,
};

class ClientBuilder {
public:
	explicit ClientBuilder(const Agent&);

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
	ClientBuilder& setConferenceFactoryUri(const std::string&);
	ClientBuilder& setCustomContact(const std::string& contact);
	ClientBuilder& setPushParams(const pushnotification::RFC8599PushParams& params);
	ClientBuilder& setInactiveAudioOnPause(OnOff);
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

	CoreClient build(const std::string&) const;

private:
	const std::shared_ptr<linphone::Factory> mFactory;
	const std::shared_ptr<linphone::Core> mCoreTemplate;
	const std::shared_ptr<linphone::AccountParams> mAccountParams;
	const Agent& mAgent;
	OnOff mLimeX3DH : 1;
	OnOff mSendVideo : 1;
	OnOff mReceiveVideo : 1;
	OnOff mSendRtcp : 1;
	OnOff mIce : 1;
	OnOff mRegister : 1;
	OnOff mSetAudioInactiveOnPause = OnOff::Off;
	AudioCodec mAudioCodec = AudioCodec::AllSupported;
	std::string mPassword{""};
	std::string mRecordFilePath{""};
	std::string mPlayFilePath;
};

} // namespace tester
} // namespace flexisip
