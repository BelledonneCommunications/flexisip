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
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "base-thread-pool.hh"

namespace flexisip {

/**
 * Provide a pool of threads for executing custom tasks.
 * This basic implementation create nThreads at creation and then they are waiting for tasks.
 */
class BasicThreadPool : public BaseThreadPool {
public:
	BasicThreadPool(unsigned int maxThreadNumber, unsigned int maxQueueSize);
	~BasicThreadPool() override;

	void stop() final;

private:
	/**
	 * This method is called by each thread.
	 */
	void _run();
};

} // namespace flexisip
