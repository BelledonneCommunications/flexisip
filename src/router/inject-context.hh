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

#include <chrono>
#include <map>
#include <memory>

namespace flexisip {

class ForkContext;
class RequestSipEvent;

/**
 * Used by ScheduleInjector to store ForkContext and the RequestSipEvent associated while waiting to inject them.
 */
class InjectContext {
	friend class ScheduleInjector;

public:
	explicit InjectContext(const std::shared_ptr<ForkContext>& fork) : mFork{fork} {};
	~InjectContext() = default;

	bool isEqual(const std::shared_ptr<ForkContext>& fork) const;
	bool isExpired() const;
	static void setMaxRequestRetentionTime(std::chrono::milliseconds maxRequestRetentionTime);

private:
	static std::chrono::milliseconds sMaxRequestRetentionTime;

	std::shared_ptr<ForkContext> mFork;
	std::shared_ptr<RequestSipEvent> waitForInject{nullptr};
	std::chrono::steady_clock::time_point mCreationDate = std::chrono::steady_clock::now();
};

} // namespace flexisip
