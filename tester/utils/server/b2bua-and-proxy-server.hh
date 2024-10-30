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

#include "b2bua/b2bua-server.hh"
#include "b2bua/sip-bridge/configuration/v1.hh"
#include "b2bua/sip-bridge/sip-bridge.hh"
#include "tester.hh"
#include "utils/server/proxy-server.hh"

namespace flexisip::tester {

using V1ProviderDesc = b2bua::bridge::config::v1::ProviderDesc;

class B2buaAndProxyServer : public Server {
public:
	explicit B2buaAndProxyServer(const std::string& configFile = std::string(),
	                             bool start = true,
	                             InjectedHooks* injectedModule = nullptr);

	explicit B2buaAndProxyServer(const std::map<std::string, std::string>& customConfig,
	                             bool start = true,
	                             InjectedHooks* injectedHooks = nullptr);

	~B2buaAndProxyServer() override;

	void startB2bua();
	void startProxy();
	/**
	 * @brief Start Proxy then B2BUA.
	 */
	void start() override;

	b2bua::bridge::SipBridge& configureExternalProviderBridge(std::initializer_list<V1ProviderDesc>&& provDescs);

	flexisip::b2bua::Application& getModule();
	std::shared_ptr<b2bua::B2buaCore>& getCore() const;
	SipUri getFirstProxyUri() const;

private:
	bool mProxyIsStarted{false};
	std::shared_ptr<flexisip::B2buaServer> mB2buaServer{};
};

} // namespace flexisip::tester