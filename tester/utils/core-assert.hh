/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <memory>

#include "flexisip/sofia-wrapper/su-root.hh"

#include "agent.hh"
#include "asserts.hh"
#include "client-core.hh"
#include "utils/bellesip-utils.hh"
#include "utils/server/proxy-server.hh"

namespace flexisip {
namespace tester {

template <const std::chrono::nanoseconds& sleepBetweenIterations = kDefaultSleepInterval>
class CoreAssert : public BcAssert<sleepBetweenIterations> {
public:
	template <class... Steppables>
	CoreAssert(Steppables&&... steppables) : BcAssert<sleepBetweenIterations>({stepperFrom(steppables)...}) {
	}

	static std::function<void()> stepperFrom(linphone::Core& core) {
		return [&core] { core.iterate(); };
	}
	static std::function<void()> stepperFrom(sofiasip::SuRoot& root) {
		using namespace std::chrono_literals;
		return [&root] { root.step(1ms); };
	}
	static std::function<void()> stepperFrom(BellesipUtils& bellesip) {
		return [&bellesip] { bellesip.stackSleep(); };
	}
	static std::function<void()> stepperFrom(const CoreClient& client) {
		return stepperFrom(*client.getCore());
	}
	static std::function<void()> stepperFrom(const Server& server) {
		return stepperFrom(*server.getRoot());
	}
	static std::function<void()> stepperFrom(const Agent* server) {
		return stepperFrom(*server->getRoot());
	}
	static std::function<void()> stepperFrom(const Agent& server) {
		return stepperFrom(*server.getRoot());
	}

	template <typename T>
	static std::function<void()> stepperFrom(const std::shared_ptr<T>& sharedPtr) {
		return stepperFrom(*sharedPtr);
	}

	template <class Steppable>
	void registerSteppable(Steppable&& steppable) {
		this->addCustomIterate(stepperFrom(steppable));
	}
};

} // namespace tester
} // namespace flexisip
