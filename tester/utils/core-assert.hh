/** SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "asserts.hh"
#include "client-core.hh"

namespace flexisip {
namespace tester {

class CoreAssert : public BcAssert {
public:
	CoreAssert(const std::vector<std::shared_ptr<linphone::Core>>& cores) {
		for (const auto& core : cores) {
			addCustomIterate([core] { core->iterate(); });
		}
	}
	CoreAssert(const std::vector<std::shared_ptr<linphone::Core>>& cores, const std::shared_ptr<flexisip::Agent>& agent)
	    : CoreAssert(cores) {
		addCustomIterate([agent] { agent->getRoot()->step(std::chrono::milliseconds(1)); });
	}

	CoreAssert(const std::shared_ptr<CoreClient>& core) {
		addCustomIterate([core] { core->getCore()->iterate(); });
	}

	CoreAssert(const std::vector<std::shared_ptr<CoreClient>>& cores) {
		for (const auto& core : cores) {
			addCustomIterate([core] { core->getCore()->iterate(); });
		}
	}

	template <class... Args>
	CoreAssert(const std::shared_ptr<CoreClient>& core, const Args&... args) : CoreAssert{args...} {
		addCustomIterate([core] { core->getCore()->iterate(); });
	}

	template <class... Args>
	CoreAssert(const std::vector<std::shared_ptr<CoreClient>>& cores, const Args&... args) : CoreAssert{args...} {
		for (const auto& core : cores) {
			addCustomIterate([core] { core->getCore()->iterate(); });
		}
	}

	template <class... Args>
	CoreAssert(const std::shared_ptr<Server>& server, const Args&... args) : CoreAssert{args...} {
		addCustomIterate([server] { server->getRoot()->step(std::chrono::milliseconds(1)); });
	}
};

} // namespace tester
} // namespace flexisip
