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

#include "flexisip/sofia-wrapper/su-root.hh"

#include "agent.hh"
#include "asserts.hh"
#include "client-core.hh"
#include "service-server/service-server.hh"
#include "utils/bellesip-utils.hh"
#include "utils/proxy-server.hh"

namespace flexisip::tester {

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
	static std::function<void()> stepperFrom(BellesipUtils& belleSip) {
		return [&belleSip] { belleSip.stackSleep(); };
	}
	static std::function<void()> stepperFrom(ServiceServer& server) {
		return [&server] { return server._run(); };
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
	template <typename Iterable>
	void registerSteppables(Iterable&& steppables) {
		for(const auto& steppable : steppables) {
			this->addCustomIterate(stepperFrom(steppable));
		}
	}
};

} // namespace flexisip::tester