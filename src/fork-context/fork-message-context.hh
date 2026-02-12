/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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
#include "fork-context-impl.hh"
#include "fork-context/branch-info.hh"
#include "fork-context/fork-message-db/fork-message-context-db.hh"

namespace flexisip {
/**
 * @brief Handle the forking of SIP chat messages (MESSAGE requests). It manages the branches of the call and processes
 * responses from them.
 */
class ForkMessageContext : public ForkContextImpl {
public:
	template <typename... Args>
	static std::shared_ptr<ForkMessageContext> make(Args&&... args) {
		return std::shared_ptr<ForkMessageContext>{new ForkMessageContext{std::forward<Args>(args)...}};
	}

	static std::shared_ptr<ForkMessageContext> restore(ForkMessageContextDb& forkContextFromDb,
	                                                   const std::weak_ptr<ForkContextListener>& forkContextListener,
	                                                   const std::weak_ptr<InjectorListener>& injectorListener,
	                                                   Agent* agent,
	                                                   const std::shared_ptr<ForkContextConfig>& config,
	                                                   const std::weak_ptr<StatPair>& counter);

	ForkMessageContextDb getDbObject();
	void restoreBranch(const BranchInfoDb& dbBranch);
#ifdef ENABLE_UNIT_TESTS
	void assertEqual(const std::shared_ptr<ForkMessageContext>& expected);
#endif
private:
	using ForkContextImpl::ForkContextImpl;
};

} // namespace flexisip