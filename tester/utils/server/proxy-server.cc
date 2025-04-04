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

#include "proxy-server.hh"

#include <optional>

#include "bctoolbox/tester.h"
#include "sofia-sip/nta_tport.h"

#include "registrar/registrar-db.hh"
#include "tester.hh"
#include "utils/test-patterns/test.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip::tester {

tport_t* getPrimaryTports(const Agent& agent) {
	return ::tport_primaries(::nta_agent_tports(agent.getSofiaAgent()));
}

const char* getFirstPort(const Agent& agent) {
	return ::tport_name(getPrimaryTports(agent))->tpn_port;
}

tport_t* getFirstTransport(const Agent& agent, sa_family_t ipAddressFamily) {
	auto* transport = getPrimaryTports(agent);

	while (transport != nullptr) {
		if (tport_get_address(transport)->ai_addr->sa_family == ipAddressFamily) {
			return transport;
		}

		transport = tport_next(transport);
	}

	throw runtime_error("could not find any transport with ipAddressFamily " + to_string(ipAddressFamily));
}

/**
 * A class to manage the flexisip proxy server
 */
Server::Server(const std::string& configFilePath, InjectedHooks* injectedHooks)
    : mInjectedModule(injectedHooks ? decltype(mInjectedModule){*injectedHooks} : std::nullopt) {

	if (!configFilePath.empty()) {
		int ret = -1;
		auto serverConfigFilePath = configFilePath;
		if (filesystem::exists(serverConfigFilePath)) {
			ret = mConfigManager->load(serverConfigFilePath);
		} else {
			serverConfigFilePath = bcTesterRes(configFilePath);
			ret = mConfigManager->load(serverConfigFilePath);
		}

		if (ret != 0) {
			BC_FAIL("Failed to load configuration file (" + serverConfigFilePath + ")");
		}

		// For testing purposes, override the auth file path to be relative to the config file.
		const auto configFolderPath = serverConfigFilePath.substr(0, serverConfigFilePath.find_last_of('/') + 1);
		auto authFilePath = mConfigManager->getRoot()
		                        ->get<flexisip::GenericStruct>("module::Authentication")
		                        ->get<flexisip::ConfigString>("file-path");
		authFilePath->set(configFolderPath + authFilePath->read());
	}

	const auto root = std::make_shared<sofiasip::SuRoot>();
	mAuthDb = std::make_shared<AuthDb>(mConfigManager);
	mRegistrarDb = std::make_shared<RegistrarDb>(root, mConfigManager);
	mAgent = std::make_shared<Agent>(root, mConfigManager, mAuthDb, mRegistrarDb);
}

Server::Server(const std::map<std::string, std::string>& customConfig, InjectedHooks* injectedHooks)
    : Server(customConfig, std::make_shared<sofiasip::SuRoot>(), injectedHooks) {
}

Server::Server(const std::map<std::string, std::string>& customConfig,
               const std::shared_ptr<sofiasip::SuRoot>& root,
               InjectedHooks* injectedHooks)
    : mInjectedModule(injectedHooks ? decltype(mInjectedModule){*injectedHooks} : std::nullopt) {
	mConfigManager->load("");

	// add minimal config if not present
	auto config = customConfig;
	config.merge(map<string, string>{// Requesting bind on port 0 to let the kernel find any available port
	                                 {"global/transports", "sip:127.0.0.1:0"},
	                                 {"module::Registrar/reg-domains", "*.example.org"}});

	for (const auto& kv : config)
		setConfigParameter(kv);

	mAuthDb = std::make_shared<AuthDb>(mConfigManager);
	mRegistrarDb = std::make_shared<RegistrarDb>(root, mConfigManager);
	mAgent = std::make_shared<Agent>(root, mConfigManager, mAuthDb, mRegistrarDb);
}

Server::~Server() {
	mAgent->unloadConfig();
}

void Server::setConfigParameter(const std::pair<std::string, std::string>& parameter) {
	const auto& key = parameter.first;
	const auto& value = parameter.second;
	auto slashPos = key.find('/');
	if (slashPos == decay_t<decltype(key)>::npos) {
		throw invalid_argument{"missing '/' in parameter name [" + key + "]"};
	}
	if (slashPos == key.size() - 1) {
		throw invalid_argument{"invalid parameter name [" + key + "]: forbidden ending '/'"};
	}
	auto sectionName = key.substr(0, slashPos);
	auto parameterName = key.substr(slashPos + 1);
	mConfigManager->getRoot()->get<GenericStruct>(sectionName)->get<ConfigValue>(parameterName)->set(value);
}

void Server::runFor(std::chrono::milliseconds duration) {
	auto beforePlusDuration = steady_clock::now() + duration;
	while (beforePlusDuration >= steady_clock::now()) {
		mAgent->getRoot()->step(100ms);
	}
}

const char* Server::getFirstPort() const {
	return tester::getFirstPort(*mAgent);
}

tport_t* Server::getFirstTransport(sa_family_t ipAddressFamily) const {
	return tester::getFirstTransport(*mAgent, ipAddressFamily);
}

void Server::start() {
	mAgent->start("", "");

	// Update transports config with the auto-assigned ports
	auto* globalTransports =
	    mConfigManager->getRoot()->get<GenericStruct>("global")->get<ConfigStringList>("transports");
	const auto previousConfigTransports = globalTransports->read();
	auto dirty = false;
	auto newConfigTransports = ""s;
	auto* activeTransport = getPrimaryTports(*mAgent);
	for (const auto& prevConfTransport : previousConfigTransports) {
		auto uri = SipUri(prevConfTransport);
		if (uri.getPort() == "0"sv) {
			BC_HARD_ASSERT(activeTransport != nullptr);
			uri = uri.replacePort(::tport_name(activeTransport)->tpn_port);
			dirty = true;
		}
		newConfigTransports += uri.str() + " ";
		activeTransport = tport_next(activeTransport);
	}
	if (!dirty) return;

	globalTransports->set(newConfigTransports);
}

} // namespace flexisip::tester
