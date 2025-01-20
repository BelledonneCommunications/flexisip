/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include <functional>

namespace flexisip {

/**
 * Interface describing a pool of threads for executing custom tasks.
 */
class ThreadPool {
public:
	using Task = std::function<void()>;

	virtual ~ThreadPool() = default;

	/**
	 * Assign a task to a thread for execution. If no thread is available
	 * while this method is called, then the task is queued until a thread
	 * has completed its task.
	 * @param[in] t the task to run.
	 * @return True on success or false when the queue is full.
	 */
	virtual bool run(Task t) = 0;

	/**
	 * Stop all the threads.
	 * After calling this method, no more task will be
	 * executed and the threads cannot be started again.
	 */
	virtual void stop() = 0;
};

} // namespace flexisip