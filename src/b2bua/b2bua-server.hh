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

#include <memory>
#include <unordered_map>
#include <variant>

#include "application.hh"
#include "b2bua-core.hh"
#include "cli.hh"
#include "flexisip/configmanager.hh"
#include "linphone++/linphone.hh"
#include "service-server/service-server.hh"
#include "utils/replaces-header.hh"

namespace flexisip {

namespace tester {
class B2buaAndProxyServer;
} // namespace tester

namespace b2bua {

// Name of the corresponding section in the configuration file
inline constexpr auto configSection = "b2bua-server";

} // namespace b2bua

class B2buaServer : public ServiceServer,
                    public std::enable_shared_from_this<B2buaServer>,
                    public linphone::CoreListener,
                    public linphone::EventListener {
public:
	friend class tester::B2buaAndProxyServer;

	// Used to flag invites emitted by the B2BUA server, so they are not re-routed back to it by the B2bua module.
	static constexpr auto& kCustomHeader = "X-Flexisip-B2BUA";

	B2buaServer(const std::shared_ptr<sofiasip::SuRoot>& root, const std::shared_ptr<ConfigManager>& cfg);
	~B2buaServer() override = default;

	void onCallStateChanged(const std::shared_ptr<linphone::Core>& core,
	                        const std::shared_ptr<linphone::Call>& call,
	                        linphone::Call::State state,
	                        const std::string& message) override;

	void onCallStateIncomingReceived(const std::shared_ptr<linphone::Call>& call);
	void onCallStateOutgoingRinging(const std::shared_ptr<linphone::Call>& call);
	void onCallStateOutgoingEarlyMedia(const std::shared_ptr<linphone::Call>& call);
	void onCallStateStreamsRunning(const std::shared_ptr<linphone::Call>& call);
	void onCallStateReferred(const std::shared_ptr<linphone::Call>& call);
	void onCallStateEnd(const std::shared_ptr<linphone::Call>& call);
	void onCallStatePausedByRemote(const std::shared_ptr<linphone::Call>& call);
	void onCallStateUpdatedByRemote(const std::shared_ptr<linphone::Call>& call);
	void onCallStateReleased(const std::shared_ptr<linphone::Call>& call);

	void onDtmfReceived(const std::shared_ptr<linphone::Core>& core,
	                    const std::shared_ptr<linphone::Call>& call,
	                    int dtmf) override;

	void onNotifyReceived(const std::shared_ptr<linphone::Core>&,
	                      const std::shared_ptr<linphone::Event>&,
	                      const std::string&,
	                      const std::shared_ptr<const linphone::Content>&) override {
		// Dummy override to prevent compilation errors (mismatch with onNotifyReceived from EventListener).
	}

	void onSubscribeReceived(const std::shared_ptr<linphone::Core>& core,
	                         const std::shared_ptr<linphone::Event>& linphoneEvent,
	                         const std::string& subscribeEvent,
	                         const std::shared_ptr<const linphone::Content>& body) override;

	void
	onMessageWaitingIndicationChanged(const std::shared_ptr<linphone::Core>& core,
	                                  const std::shared_ptr<linphone::Event>& event,
	                                  const std::shared_ptr<const linphone::MessageWaitingIndication>& mwi) override;

	void onNotifyReceived(const std::shared_ptr<linphone::Event>& event,
	                      const std::shared_ptr<const linphone::Content>& content) override;

	void onSubscribeReceived(const std::shared_ptr<linphone::Event>&) override {
		// Dummy override to prevent compilation errors (mismatch with onSubscribeReceived from CoreListener).
	}

	void onSubscribeStateChanged(const std::shared_ptr<linphone::Event>& event,
	                             linphone::SubscriptionState state) override;

	int getTcpPort() const;
	int getUdpPort() const;
	const b2bua::Application& getApplication() const;

protected:
	void _init() override;
	void _run() override;
	std::unique_ptr<AsyncCleanup> _stop() override;

private:
	struct EventInfo {
		std::weak_ptr<linphone::Event> peerEvent;
		bool isLegA;
	};

	/**
	 * @brief Retrieve peer call that is linked to the given call.
	 *
	 * @param call call leg
	 * @return peer call leg or nullptr if not found
	 */
	std::shared_ptr<linphone::Call> getPeerCall(const std::shared_ptr<linphone::Call>& call) const;

	/**
	 * @brief Return legB call if the given call in Replace header is a legA.
	 *
	 * @param replacesHeader the 'Replaces' header to inspect
	 * @return peer call legB or nullptr if the call in the 'Replace' header is already a legB or not found
	 */
	std::shared_ptr<linphone::Call> findPeerReplacingCall(const b2bua::ReplacesHeader& replacesHeader) const;

	std::shared_ptr<ConfigManager> mConfigManager;
	CommandLineInterface mCli;
	std::shared_ptr<b2bua::B2buaCore> mCore;
	std::unordered_map<std::shared_ptr<linphone::Call>, std::weak_ptr<linphone::Call>> mPeerCalls;
	std::unordered_map<std::shared_ptr<linphone::Event>, EventInfo> mPeerEvents;
	std::unique_ptr<b2bua::Application> mApplication = nullptr;
	const std::string mLogPrefix{"B2buaServer"};
};

} // namespace flexisip