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

#include "b2bua-and-proxy-server.hh"

#include "utils/socket-address.hh"

using namespace std;

namespace flexisip::tester {

B2buaAndProxyServer::B2buaAndProxyServer(const std::string& configFilePath, bool start, InjectedHooks* injectedModule)
    : Server(configFilePath, injectedModule) {
	mB2buaServer = make_shared<flexisip::B2buaServer>(this->getRoot(), this->getConfigManager());
	if (start) this->start();
}

B2buaAndProxyServer::B2buaAndProxyServer(const std::map<std::string, std::string>& customConfig,
                                         bool start,
                                         InjectedHooks* injectedHooks)
    : Server{customConfig, injectedHooks} {
	mB2buaServer = make_shared<flexisip::B2buaServer>(this->getRoot(), this->getConfigManager());
	if (start) this->start();
}

B2buaAndProxyServer::~B2buaAndProxyServer() {
	std::ignore = mB2buaServer->stop();
}

void B2buaAndProxyServer::startB2bua() {
	const auto& configRoot = *getConfigManager()->getRoot();
	const auto& b2buaConfig = *configRoot.get<GenericStruct>("b2bua-server");

	// Need a writable dir to store DTLS-SRTP self-signed certificate (even if the config file is empty).
	// Force to use writable-dir instead of var directory.
	b2buaConfig.get<ConfigString>("data-directory")->set(bcTesterWriteDir());

	// Start B2BUA server.
	mB2buaServer->init();

	if (!mProxyIsStarted) return;

	// Set module::B2bua/b2bua-server parameter value so the proxy server will be able to route requests to the
	// B2BUA server.
	SipUri b2buaServerConfigUri{b2buaConfig.get<ConfigString>("transport")->read()};
	string b2buaUri{b2buaServerConfigUri.str()};
	if (b2buaServerConfigUri.getPort() == "0" /* if port is dynamically chosen by the kernel */) {
		auto b2buaPort = mB2buaServer->getUdpPort();
		if (b2buaServerConfigUri.hasParam("transport")) {
			const auto parameter = b2buaServerConfigUri.getParam("transport");
			if (string_utils::iequals(parameter, "tcp") or string_utils::iequals(parameter, "tls")) {
				b2buaPort = mB2buaServer->getTcpPort();
			}
		}

		b2buaUri = SipUri{b2buaServerConfigUri}.replacePort(std::to_string(b2buaPort)).str();
	}
	const auto& b2buaModuleConfig = *configRoot.get<GenericStruct>("module::B2bua");
	b2buaModuleConfig.get<ConfigString>("b2bua-server")->set(b2buaUri);
	// Reload module::B2bua.
	getAgent()->findModule("B2bua")->reload();
}

void B2buaAndProxyServer::startProxy() {
	// Start proxy server.
	Server::start();
	mProxyIsStarted = true;

	const auto& configRoot = *getConfigManager()->getRoot();
	const auto& globalConfig = *configRoot.get<GenericStruct>("global");
	const auto& b2buaConfig = *configRoot.get<GenericStruct>("b2bua-server");

	// The B2BUA server needs an outbound proxy to route all SIP messages to the proxy, set it to the first
	// transport of the proxy.
	SipUri proxyConfigUri{globalConfig.get<ConfigStringList>("transports")->read().front()};
	SipUri proxyUri{proxyConfigUri};
	if (proxyConfigUri.getPort() == "0" /* if port is dynamically chosen by the kernel */) {
		proxyUri = getFirstProxyUri();
	}
	b2buaConfig.get<ConfigString>("outbound-proxy")->set(proxyUri.str());
}

void B2buaAndProxyServer::start() {
	startProxy();
	startB2bua();
}

b2bua::bridge::SipBridge&
B2buaAndProxyServer::configureExternalProviderBridge(std::initializer_list<V1ProviderDesc>&& provDescs) {
	using namespace b2bua::bridge;
	mB2buaServer->mApplication = make_unique<SipBridge>(this->getRoot(), mB2buaServer->mCore,
	                                                    config::v2::fromV1(vector<V1ProviderDesc>(provDescs)),
	                                                    getAgent()->getConfigManager().getRoot());
	return dynamic_cast<SipBridge&>(*mB2buaServer->mApplication);
}

flexisip::b2bua::Application& B2buaAndProxyServer::getModule() {
	return *mB2buaServer->mApplication;
}

std::shared_ptr<b2bua::B2buaCore>& B2buaAndProxyServer::getCore() const {
	return mB2buaServer->mCore;
}

SipUri B2buaAndProxyServer::getFirstProxyUri() const {
	if (!mProxyIsStarted) return SipUri{};

	const auto& configRoot = *getConfigManager()->getRoot();
	const auto& globalConfig = *configRoot.get<GenericStruct>("global");

	SipUri proxyConfigUri{globalConfig.get<ConfigStringList>("transports")->read().front()};
	const auto* proxyAddr = tport_get_address(Server::getFirstTransport(AF_INET));
	if (!proxyAddr) throw runtime_error{"proxy server does not listen on at least one IPv4 address"};
	const auto socketAddress = SocketAddress::make(reinterpret_cast<su_sockaddr_t*>(proxyAddr->ai_addr));
	const auto params = proxyConfigUri.getParams();
	return SipUri{proxyConfigUri.getScheme() + ":" + socketAddress->str() + (params.empty() ? "" : ";" + params)};
}

} // namespace flexisip::tester