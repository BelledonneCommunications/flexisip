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

#include <filesystem>

#include "linphone++/linphone.hh"

#include "call-handler.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/utils/sip-uri.hh"
#include "service-server/service-server.hh"
#include "utils/transport/http/rest-client.hh"

namespace flexisip {

namespace voicemail {
// Name of the corresponding section in the configuration file
inline constexpr auto configSection = "voicemail-server";
} // namespace voicemail

class VoicemailServer : public ServiceServer,
                        public std::enable_shared_from_this<VoicemailServer>,
                        public linphone::CoreListener,
                        public voicemail::CallHandlerObserver {
public:
	VoicemailServer(const std::shared_ptr<sofiasip::SuRoot>& root, const std::shared_ptr<ConfigManager>& cfg);
	~VoicemailServer() override = default;

	void _init() override;
	void _run() override;
	std::unique_ptr<AsyncCleanup> _stop() override;

	void onCallStateChanged(const std::shared_ptr<linphone::Core>& core,
	                        const std::shared_ptr<linphone::Call>& call,
	                        linphone::Call::State state,
	                        const std::string& message) override;

	void onCallStateError(const std::shared_ptr<linphone::Call>& call);
	void onCallHandled(const std::shared_ptr<linphone::Call>& call) noexcept override;

	int getTcpPort() const {
		return mCore->getTransportsUsed()->getTcpPort();
	}

private:
	static constexpr std::string_view mLogPrefix{"VoicemailServer"};

	void onCallStateIncomingReceived(const std::shared_ptr<linphone::Call>& call);

	std::shared_ptr<linphone::Core> mCore{};

	std::shared_ptr<ConfigManager> mConfigManager{};
	RestClient mFlexiApiClient;
	voicemail::CallHandler::RecordingParameters mRecordingParameters;
	voicemail::CallHandler::AnnouncementPaths mAnnouncementsPaths{};

	std::map<std::string, const std::shared_ptr<voicemail::CallHandler>> mCallHandlers{};
};

} // namespace flexisip