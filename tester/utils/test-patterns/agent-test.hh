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

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "registrar/registrar-db.hh"

#include "test.hh"

namespace flexisip {
namespace tester {

/**
 * Run the SofiaSip main loop until a given condition is fulfil or the timeout is reached.
 * @return true, if the break condition has been fulfil before the timeout.
 */
template <typename Duration>
inline bool
rootStepFor(std::shared_ptr<sofiasip::SuRoot> root, const std::function<bool()>& breakCondition, Duration timeout) {
	using namespace std::chrono;
	using clock_type = steady_clock;

	auto now = clock_type::now();
	auto end = now + duration_cast<clock_type::duration>(timeout);
	for (; now < end; now = clock_type::now()) {
		if (breakCondition()) return true;

		// The main loop step must not exceed 50ms in order the break condition be evaluated several times.
		auto stepTimeout = std::min(duration_cast<milliseconds>(end - now), 50ms);
		root->step(stepTimeout);
	}
	return false;
}

// Base class for all the tests which needs a running Agent.
// It automatically instantiates an Agent which can be configured
// by redefining onAgentConfiguration() method. Furthermore, it
// ensures that the RegistrarDB singleton is destroyed once the test
// is completed.
// The test can be specialized by overriding onExec() method.
class AgentTest : public Test {
public:
	AgentTest(bool runAgent = true) noexcept : mRunAgent{runAgent} {
		mConfigManager->load("");
		mAuthDbOwner = std::make_shared<AuthDbBackendOwner>(mConfigManager);
	}

	virtual ~AgentTest() = default;

	void operator()() final {
		configureAgent();
		mRegistrarDb = std::make_shared<RegistrarDb>(mRoot, mConfigManager);
		mAgent = std::make_shared<Agent>(mRoot, mConfigManager, mAuthDbOwner, mRegistrarDb);
		onAgentConfigured();
		if (mRunAgent) {
			mAgent->start("", "");
			onAgentStarted();
		}
		onTestInit();
		testExec();
	};

protected:
	// Protected methods
	void configureAgent() {
		onAgentConfiguration(*mConfigManager);
	};

	/**
	 * Run the SofiaSip main loop for a given time.
	 * This methods is to be used by an overload of testExec().
	 */
	template <typename Duration>
	void waitFor(Duration timeout) noexcept {
		waitFor([]() { return false; }, timeout);
	}

	/**
	 * Run the SofiaSip main loop until a given condition is fulfil or the timeout is reached.
	 * This methods is to be used by an overload of testExec().
	 * @return true, if the break condition has been fulfil before the timeout.
	 */
	template <typename Duration>
	bool waitFor(const std::function<bool()>& breakCondition, Duration timeout) {
		return rootStepFor(mRoot, breakCondition, timeout);
	}

	/**
	 * This method is called before agent creation.
	 * It enables to change the configuration.
	 */
	virtual void onAgentConfiguration(ConfigManager& cfg) {
		auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigBoolean>("enable-snmp")->set("false");
	}

	virtual void onAgentStarted() {
	}

	/**
	 * This method is called after agent creation, but before it starts.
	 */
	virtual void onAgentConfigured() {
	}

	/**
	 * This method is the last called before testExec.
	 */
	virtual void onTestInit() {
	}

	virtual void testExec() = 0;

	// Protected attributes
	std::shared_ptr<sofiasip::SuRoot> mRoot{std::make_shared<sofiasip::SuRoot>()};
	std::shared_ptr<ConfigManager> mConfigManager{std::make_shared<ConfigManager>()};
	std::shared_ptr<AuthDbBackendOwner> mAuthDbOwner;
	std::shared_ptr<RegistrarDb> mRegistrarDb;
	std::shared_ptr<Agent> mAgent;
	bool mRunAgent;
};

} // namespace tester
} // namespace flexisip
