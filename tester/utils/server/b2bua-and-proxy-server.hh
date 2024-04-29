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
private:
	std::shared_ptr<flexisip::B2buaServer> mB2buaServer;

public:
	explicit B2buaAndProxyServer(const std::string& configFile = std::string(),
	                             bool start = true,
	                             InjectedHooks* injectedModule = nullptr)
	    : Server(configFile, injectedModule) {

		// Configure B2bua Server
		auto* b2buaServerConf = getConfigManager()->getRoot()->get<GenericStruct>("b2bua-server");

		if (!configFile.empty()) {
			// b2bua server needs an outbound proxy to route all sip messages to the proxy, set it to the first
			// transport of the proxy.
			auto proxyTransports = getAgent()
			                           ->getConfigManager()
			                           .getRoot()
			                           ->get<GenericStruct>("global")
			                           ->get<ConfigStringList>("transports")
			                           ->read();
			b2buaServerConf->get<ConfigString>("outbound-proxy")->set(proxyTransports.front());
		}

		// need a writable dir to store DTLS-SRTP self signed certificate (even if the config file is empty)
		// Force to use writable-dir instead of var directory
		b2buaServerConf->get<ConfigString>("data-directory")->set(bcTesterWriteDir());

		mB2buaServer = std::make_shared<flexisip::B2buaServer>(this->getRoot(), this->getConfigManager());

		if (start) {
			this->start();
		}
	}
	~B2buaAndProxyServer() override {
		std::ignore = mB2buaServer->stop();
	}

	void init() {
		mB2buaServer->init();
	}

	void start() override {
		init();

		// Configure module b2bua
		const auto* configRoot = getAgent()->getConfigManager().getRoot();
		const auto& transport = configRoot->get<GenericStruct>("b2bua-server")->get<ConfigString>("transport")->read();
		configRoot->get<GenericStruct>("module::B2bua")->get<ConfigString>("b2bua-server")->set(transport);

		// Start proxy
		Server::start();
	}

	auto& configureExternalProviderBridge(std::initializer_list<V1ProviderDesc>&& provDescs) {
		using namespace b2bua::bridge;
		mB2buaServer->mApplication =
		    std::make_unique<SipBridge>(std::make_shared<sofiasip::SuRoot>(), mB2buaServer->mCore,
		                                config::v2::fromV1(std::vector<V1ProviderDesc>(std::move(provDescs))),
		                                getAgent()->getConfigManager().getRoot());
		return static_cast<SipBridge&>(*mB2buaServer->mApplication);
	}

	flexisip::b2bua::Application& getModule() {
		return *mB2buaServer->mApplication;
	}

	auto& getCore() const {
		return mB2buaServer->mCore;
	}
};
} // namespace flexisip::tester