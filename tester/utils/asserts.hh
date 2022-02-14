/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <chrono>
#include <functional>
#include <thread>

#include "flexisip/agent.hh"
#include "linphone++/linphone.hh"

class BcAssert {
public:
	void addCustomIterate(const std::function<void()>& iterate) {
		mIterateFuncs.push_back(iterate);
	}
	bool waitUntil(std::chrono::duration<double> timeout, const std::function<bool()>& condition) {
		auto start = std::chrono::steady_clock::now();

		bool result;
		while (!(result = condition()) && (std::chrono::steady_clock::now() - start < timeout)) {
			for (const auto& iterate : mIterateFuncs) {
				iterate();
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
		return result;
	}
	bool wait(const std::function<bool()>& condition) {
		return waitUntil(std::chrono::seconds(2), condition);
	}

private:
	std::list<std::function<void()>> mIterateFuncs;
};

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
};
