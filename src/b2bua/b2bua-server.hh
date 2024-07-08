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

#include <memory>
#include <regex>
#include <variant>

#include "linphone++/linphone.hh"

#include "flexisip/configmanager.hh"

#include "cli.hh"
#include "service-server/service-server.hh"

namespace flexisip {

namespace tester {
namespace b2buatester {
class B2buaServer;
}
} // namespace tester

namespace b2bua {
// Name of the corresponding section in the configuration file
constexpr auto configSection = "b2bua-server";

class Application {
public:
	using DeclineCall = linphone::Reason;
	using InviteAddress = std::shared_ptr<const linphone::Address>;
	using ActionToTake = std::variant<DeclineCall, InviteAddress>;

	virtual ~Application() = default;

	virtual void init(const std::shared_ptr<linphone::Core>& core, const ConfigManager& cfg) = 0;
	/**
	 * lets the application run some business logic before the outgoing call is placed.
	 *
	 * @param[in]	incomingCall	the call that triggered the B2BUA.
	 * @param[inout]	callee	the address to call, can be mangled according to internal business logic.
	 * @param[inout]	outgoingCallParams	the params of the outgoing call to be created. They will be modified
	 *according to the business logic of the application.
	 * @return		a reason to abort the bridging and decline the incoming call. Reason::None if the call should go
	 *through.
	 **/
	virtual ActionToTake onCallCreate(const linphone::Call& incomingCall, linphone::CallParams& outgoingCallParams) = 0;
	virtual void onCallEnd([[maybe_unused]] const linphone::Call& call) {
	}
};

} // namespace b2bua

class B2buaServer : public ServiceServer,
                    public std::enable_shared_from_this<B2buaServer>,
                    public linphone::CoreListener {
public:
	friend class tester::b2buatester::B2buaServer;

	static constexpr auto& kConfKey = "b2bua::confData";
	// Used to flag invites emitted by the B2BUA so they are not re-routed back to it by the B2bua module
	static constexpr auto& kCustomHeader = "X-Flexisip-B2BUA";

	B2buaServer(const std::shared_ptr<sofiasip::SuRoot>& root, const std::shared_ptr<ConfigManager>& cfg);
	~B2buaServer();

	void onCallStateChanged(const std::shared_ptr<linphone::Core>& core,
	                        const std::shared_ptr<linphone::Call>& call,
	                        linphone::Call::State state,
	                        const std::string& message) override;
	void onDtmfReceived(const std::shared_ptr<linphone::Core>& core,
	                    const std::shared_ptr<linphone::Call>& call,
	                    int dtmf) override;

	int getTcpPort() const {
		return mCore->getTransportsUsed()->getTcpPort();
	}

	int getUdpPort() const {
		return mCore->getTransportsUsed()->getUdpPort();
	}

	const b2bua::Application& getApplication() const {
		return *mApplication;
	}

protected:
	void _init() override;
	void _run() override;
	std::unique_ptr<AsyncCleanup> _stop() override;

private:
	std::shared_ptr<ConfigManager> mConfigManager;
	CommandLineInterface mCli;
	std::shared_ptr<linphone::Core> mCore;
	std::unique_ptr<b2bua::Application> mApplication = nullptr;
};

} // namespace flexisip
