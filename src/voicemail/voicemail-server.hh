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

namespace flexisip {

namespace voicemail {
// Name of the corresponding section in the configuration file
inline constexpr auto configSection = "voicemail-server";
} // namespace voicemail

class VoicemailServer : public ServiceServer,
                        public std::enable_shared_from_this<VoicemailServer>,
                        public linphone::CoreListener {
public:
	VoicemailServer(const std::shared_ptr<sofiasip::SuRoot>& root, const std::shared_ptr<ConfigManager>& cfg)
	    : ServiceServer(root), mConfigManager(cfg) {
	}
	~VoicemailServer() = default;

	void onCallStateChanged(const std::shared_ptr<linphone::Core>& core,
	                        const std::shared_ptr<linphone::Call>& call,
	                        linphone::Call::State state,
	                        const std::string& message) override;

protected:
	void _init() override;
	void _run() override;
	std::unique_ptr<AsyncCleanup> _stop() override;

	SipUri mTransport{};

private:
	static constexpr std::string_view mLogPrefix{"VoicemailServer"};

	void onCallStateIncomingReceived(const std::shared_ptr<linphone::Call>& call);
	void onCallStateStreamsRunning(const std::shared_ptr<linphone::Call>& call);
	void onCallStateEnd(const std::shared_ptr<linphone::Call>& call);

	std::shared_ptr<linphone::Core> mCore{};
	std::shared_ptr<ConfigManager> mConfigManager{};
	std::filesystem::path mAnnouncementFile{};
	std::map<std::string, const std::shared_ptr<CallHandler>> mCallHandlers{};
};

} // namespace flexisip