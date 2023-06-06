/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include <linphone++/linphone.hh>

namespace flexisip {
namespace pushnotification {

class RFC8599PushParams;

}
namespace tester {

class Server;
class CoreClient;

enum class OnOff : bool {
	Off = 0,
	On = 1,
};

enum class VideoDevice : std::uint8_t {
	Disabled = 0,
	// Use Mire as camera for video stream
	Mire = 1,
};

class ClientBuilder {
public:
	explicit ClientBuilder(const Server&);

	ClientBuilder(ClientBuilder&&) = default;
	// We don't want to share e.g. AccountParams between builders
	ClientBuilder(const ClientBuilder&) = delete;

	void setConferenceFactoryUri(const std::string&);
	void setLimeX3DH(OnOff);
	void setVideoDevice(VideoDevice);
	ClientBuilder& setCustomContact(const std::string& contact);
	ClientBuilder& setPushParams(const pushnotification::RFC8599PushParams& params);
	/**
	 * Add some Apple-specific push info to REGISTERs
	 */
	ClientBuilder& setApplePushConfig();
	ClientBuilder& setPassword(const std::string_view& password);

	CoreClient build(const std::string&) const;

private:
	const std::shared_ptr<linphone::Factory> mFactory;
	const std::shared_ptr<linphone::Core> mCoreTemplate;
	const std::shared_ptr<linphone::AccountParams> mAccountParams;
	const Server& mServer;
	OnOff mLimeX3DH : 1;
	VideoDevice mVideoDevice{VideoDevice::Disabled};
	std::string mPassword{""};
};

} // namespace tester
} // namespace flexisip
