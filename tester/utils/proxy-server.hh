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

#include <chrono>
#include <map>
#include <memory>
#include <string>

#include "flexisip/sofia-wrapper/su-root.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "injected-module-info.hh"
#include "registrar/registrar-db.hh"

namespace flexisip {
namespace tester {

const char* getFirstPort(const Agent& agent);

/**
 * A class to manage the flexisip proxy server
 */
class Server {
public:
	/**
	 * @brief Create a SofiaSip root, an Agent and load the config file given as parameter.
	 * @param[in] configFile The path to the config file. Search for it in the resource directory
	 * and TESTER_DATA_DIR. An empty path will cause the Agent to use its default configuration.
	 * @param injectedModule A module to be injected into the Agent's module chain to mangle requests before they reach
	 * other modules.
	 */
	explicit Server(const std::string& configFile = "", InjectedHooks* injectedHooks = nullptr);
	/**
	 * @brief Same as before but use a map instead of a file to configure the agent.
	 * Default transport is set to localhost and port 0.
	 * Default reg-domain is set to *.example.org.
	 * @param customConfig Agent configuration as a map. The key is the name of the paramter
	 * to change (e.g. 'module::Registrar/reg-domains') and the value is the new
	 * value of the parameter as string.
	 * @param injectedModule A module to be injected into the Agent's module chain to mangle requests before they reach
	 * other modules.
	 */
	explicit Server(const std::map<std::string, std::string>& customConfig, InjectedHooks* injectedHooks = nullptr);
	/**
	 * @brief Same as before but use a map instead of a file to configure the agent.
	 * Default transport is set to localhost and port 0.
	 * Default reg-domain is set to *.example.org.
	 * @param customConfig Agent configuration as a map. The key is the name of the paramter
	 * to change (e.g. 'module::Registrar/reg-domains') and the value is the new
	 * value of the parameter as string.
	 * @param root An external root to share.
	 * @param injectedModule A module to be injected into the Agent's module chain to mangle requests before they reach
	 * other modules.
	 */
	explicit Server(const std::map<std::string, std::string>& customConfig,
	                const std::shared_ptr<sofiasip::SuRoot>& root,
	                InjectedHooks* injectedHooks = nullptr);

	virtual ~Server();

	// Accessors
	const std::shared_ptr<sofiasip::SuRoot>& getRoot() const noexcept {
		return mAgent->getRoot();
	}

	const std::shared_ptr<ConfigManager>& getConfigManager() const noexcept {
		return mConfigManager;
	}

	const std::shared_ptr<RegistrarDb>& getRegistrarDb() const noexcept {
		return mRegistrarDb;
	}

	const std::shared_ptr<flexisip::Agent>& getAgent() const noexcept {
		return mAgent;
	}

	const char* getFirstPort() const;
	tport_t* getFirstTransport(sa_family_t ipAddressFamily) const;

	/**
	 * @brief Start the Agent.
	 */
	virtual void start() {
		mAgent->start("", "");
	}

	/**
	 * @brief Run the main loop for a given time.
	 */
	void runFor(std::chrono::milliseconds duration);

private:
	const std::optional<InjectedModuleInfo> mInjectedModule{std::nullopt};
	std::shared_ptr<ConfigManager> mConfigManager{std::make_shared<ConfigManager>()};
	std::shared_ptr<AuthDbBackendOwner> mAuthDbOwner;
	std::shared_ptr<RegistrarDb> mRegistrarDb;
	std::shared_ptr<flexisip::Agent> mAgent;
}; // Class Server

} // namespace tester
} // namespace flexisip
