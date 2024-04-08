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
/*
    Tools to bridge calls to other SIP providers via the Back-to-Back User Agent
    E.g. for placing PSTN calls

    NOT thread safe
*/

#pragma once

#include <unordered_map>

#include "linphone++/linphone.hh"

#include "b2bua/b2bua-server.hh"
#include "b2bua/sip-bridge/accounts/account.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "b2bua/sip-bridge/sip-provider.hh"
#include "cli.hh"

namespace flexisip::b2bua::bridge {

using AccountPoolImplMap = std::unordered_map<config::v2::AccountPoolName, std::shared_ptr<AccountPool>>;
class SipBridge : public b2bua::Application, public CliHandler {
public:
	SipBridge(const std::shared_ptr<sofiasip::SuRoot>& suRoot, const std::shared_ptr<linphone::Core>& core = nullptr)
	    : mSuRoot{suRoot}, mCore{core} {};

	SipBridge(const std::shared_ptr<sofiasip::SuRoot>& suRoot,
	          const std::shared_ptr<linphone::Core>& core,
	          config::v2::Root&& rootConf,
	          const GenericStruct* globalConfigRoot);

	void init(const std::shared_ptr<linphone::Core>& core, const flexisip::ConfigManager& config) override;

	ActionToTake onCallCreate(const linphone::Call& incomingCall, linphone::CallParams& outgoingCallParams) override;
	void onCallEnd(const linphone::Call& call) override;

	ActionToTake onSubscribe(const linphone::Event& event, const std::string& subscribeEvent) override;

	std::string handleCommand(const std::string& command, const std::vector<std::string>& args) override;

	const std::vector<SipProvider>& getProviders() const {
		return providers;
	}

private:
	AccountPoolImplMap getAccountPoolsFromConfig(config::v2::AccountPoolConfigMap& accountPoolConfigMap);
	void initFromRootConfig(config::v2::Root rootConfig);

	std::shared_ptr<sofiasip::SuRoot> mSuRoot;
	std::shared_ptr<linphone::Core> mCore;
	const GenericStruct* mGlobalConfigRoot = nullptr;
	std::vector<SipProvider> providers;
	std::unordered_map<std::string, std::weak_ptr<Account>> occupiedSlots;
};

} // namespace flexisip::b2bua::bridge
