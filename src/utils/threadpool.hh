/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010  Belledonne Communications SARL.

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


#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>


namespace flexisip {

/**
 * Provide a pool of threads for executing custom tasks.
 */
class ThreadPool {
public:
	using Task = std::function<void()>;

	/**
	 * Constructor.
	 * @param[in] nThreads number of threads in the pool.
	 * @param[in] maxQueueSize maximum number of task that can be queued.
	 */
	ThreadPool(unsigned int nThreads, unsigned int maxQueueSize);
	~ThreadPool();

	/**
	 * Assign a task to a thread for execution. If no thread is available
	 * while this method is called, then the task is queued until a thread
	 * has completed its task.
	 * @param[in] t the task to run.
	 * @return True on success or false when the queue is full.
	 */
	bool run(Task t);

	/**
	 * Stop all the threads.
	 * After calling this method, no more task will be
	 * executed and the threads cannot be started again.
	 */
	void stop();

private:
	enum State {
		Running,
		Shutdown,
		Stopped
	};

	/**
	 * This methed is called by each thread.
	 */
	void _run();

	std::vector<std::thread> mThreadPool;
	std::queue<Task> mTasks;
	std::mutex mTasksMutex;
	std::condition_variable mCondition;
	unsigned mMaxQueueSize;
	State mState = Running;
};


} // namespace flexisip
