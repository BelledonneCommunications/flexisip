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

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "flexisip/fork-stats.hh"
#include "flexisip/module.hh"

namespace flexisip {
struct RouterStats {
	std::shared_ptr<ForkStats> mForkStats;
};

class Injector;
class Agent;
class Record;
class ForkManager;
class SpacesStore;

class ModuleRouter : public Module, public std::enable_shared_from_this<ModuleRouter> {

	friend std::shared_ptr<Module> ModuleInfo<ModuleRouter>::create(Agent*);

public:
	~ModuleRouter() override;

	void onLoad(const GenericStruct* mc) override;
	void onUnload() override {}

	std::unique_ptr<RequestSipEvent> onRequest(std::unique_ptr<RequestSipEvent>&& ev) override;

	static void onResponse(ResponseSipEvent& ev);
	std::unique_ptr<ResponseSipEvent> onResponse(std::unique_ptr<ResponseSipEvent>&& ev) override;

	static void sendReply(Agent* agent,
	                      RequestSipEvent& ev,
	                      int code,
	                      const char* reason,
	                      int warn_code = 0,
	                      const char* warning = nullptr);

	bool isManagedDomain(const url_t* url) const;

	static void declareConfig(GenericStruct& moduleConfig);

	std::shared_ptr<const ForkManager> getForkManager() const {
		return mForkManager;
	}

	RouterStats mStats{};

protected:
	ModuleRouter(Agent* ag, const ModuleInfoBase* moduleInfo);

	static std::vector<std::string> split(const char* data, const char* delim);

	/**
	 * Allows executing the 'dispatch' function (creation of a new branch) under specific conditions.
	 */
	void setDispatchFilter(const std::function<bool(const sip_t*)>& filter);

private:
	static ModuleInfo<ModuleRouter> sInfo;

	bool mResolveRoutes{};
	std::list<std::string> mDomains{};
	std::shared_ptr<ForkManager> mForkManager{};
	std::shared_ptr<SpacesStore> mSpacesStore{};
};

} // namespace flexisip