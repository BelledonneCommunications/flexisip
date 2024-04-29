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

class CoreAssert : public BcAssert {
public:
	template <class... Steppables>
	CoreAssert(Steppables&&... steppables) : BcAssert({stepperFrom(steppables)...}) {
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
	static std::function<void()> stepperFrom(const std::shared_ptr<linphone::Core>& core) {
		return stepperFrom(*core);
	}
	static std::function<void()> stepperFrom(const CoreClient& client) {
		return stepperFrom(*client.getCore());
	}
	static std::function<void()> stepperFrom(const std::shared_ptr<CoreClient>& client) {
		return stepperFrom(*client->getCore());
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
	/**
	 * @param server shared_ptr to either a tester::Server or a flexisip::Agent.
	 */
	template <typename ServerT>
	static std::function<void()> stepperFrom(const std::shared_ptr<ServerT>& server) {
		return stepperFrom(*server->getRoot());
	}

	template <class Steppable>
	void registerSteppable(Steppable&& steppable) {
		addCustomIterate(stepperFrom(steppable));
	}
};

} // namespace tester
} // namespace flexisip
