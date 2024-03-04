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

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "base-thread-pool.hh"

namespace flexisip {

/**
 * Provide a pool of threads for executing custom tasks.
 * This implementation only create one main thread at start, this thread is in charge of creating new threads to handle
 * tasks.
 */
class AutoThreadPool : public BaseThreadPool {
public:
	AutoThreadPool(unsigned int maxThreadNumber, unsigned int maxQueueSize);
	~AutoThreadPool() override;

	void stop() final;

	static std::unique_ptr<AutoThreadPool>& getDbThreadPool(unsigned int maxThreadNumber);

private:
	/**
	 * This method is called by the main thread.
	 */
	void _run();

	/**
	 * This method is called by sub threads.
	 */
	void _subThreadRun(Task initialTask);

	std::unique_ptr<std::thread> mainThread{};
	std::atomic_uint mCurrentThreadNumber{0};

	static std::unique_ptr<AutoThreadPool> sDbThreadPool;
};

} // namespace flexisip
