/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <flexisip/agent.hh>
#include <flexisip/registrar/registrar-db.hh>

#include "test.hh"

namespace flexisip {
namespace tester {

// Base class for all the tests which needs a running Agent.
// It automatically instantiates an Agent which can be configured
// by redefining onAgentConfiguration() method. Furthermore, it
// ensures that the RegistrarDB singleton is destroyed once the test
// is completed.
// The test can be specialized by overriding onExec() method.
class AgentTest : public Test {
public:
	AgentTest(bool runAgent = true) noexcept : mRunAgent{runAgent} {
	}

	~AgentTest() {
		RegistrarDb::resetDB();
	}

	void operator()() override {
		configureAgent();
		onAgentConfigured();
		if (mRunAgent) {
			mAgent->start("", "");
			onAgentStarted();
		}
		testExec();
	};

protected:
	// Protected methods
	void configureAgent() {
		auto* cfg = GenericManager::get();
		cfg->load("");
		onAgentConfiguration(*cfg);
		mAgent->loadConfig(cfg, false);
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
		using namespace std::chrono;
		using clock_type = steady_clock;

		auto now = clock_type::now();
		auto end = now + duration_cast<clock_type::duration>(timeout);
		for (; now < end; now = clock_type::now()) {
			if (breakCondition()) return true;

			// The main loop step must not exceed 50ms in order the break condition be evaluated several times.
			auto stepTimeout = std::min(duration_cast<milliseconds>(end - now), 50ms);
			mRoot->step(stepTimeout);
		}
		return false;
	}

	virtual void onAgentConfiguration(GenericManager& cfg) {
		auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigBoolean>("enable-snmp")->set("false");
	}

	virtual void onAgentStarted() {
	}

	virtual void onAgentConfigured() {
	}

	virtual void testExec() = 0;

	// Protected attributes
	std::shared_ptr<sofiasip::SuRoot> mRoot{std::make_shared<sofiasip::SuRoot>()};
	std::shared_ptr<Agent> mAgent{std::make_shared<Agent>(mRoot)};
	bool mRunAgent;
};

} // namespace tester
} // namespace flexisip
