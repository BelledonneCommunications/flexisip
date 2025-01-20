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

#include "flexisip/logmanager.hh"

#include "basic-thread-pool.hh"

using namespace std;

namespace flexisip {

BasicThreadPool::BasicThreadPool(unsigned int maxThreadNumber, unsigned int maxQueueSize)
    : BaseThreadPool(maxQueueSize, maxThreadNumber) {
	SLOGD << "BasicThreadPool [" << this << "]: init with " << maxThreadNumber << " threads and queue size "
	      << maxQueueSize;

	// Create number of required threads and add them to the thread pool vector.
	for (unsigned int i = 0; i < mMaxThreadNumber; i++) {
		mThreadPool.emplace_back(&BasicThreadPool::_run, this);
	}
}

BasicThreadPool::~BasicThreadPool() {
	if (mState != Stopped) stop();
}

void BasicThreadPool::stop() {
	SLOGD << "BasicThreadPool [" << this << "]: shutdown";
	// Scope based locking.
	{
		// Put unique lock on task mutex.
		unique_lock<mutex> lock(mTasksMutex);

		// Set termination flag to true.
		mState = Shutdown;
	}

	// Wake up all threads.
	mCondition.notify_all();

	// Join all threads.
	for (auto& thread : mThreadPool) {
		thread.join();
	}

	// Empty workers vector.
	mThreadPool.clear();

	// Indicate that the pool has been shut down.
	mState = Stopped;
}

void BasicThreadPool::_run() {
	Task task;
	while (true) {
		// Scope based locking.
		{
			// Put unique lock on task mutex.
			unique_lock<mutex> lock(mTasksMutex);

			// Wait until queue is not empty or termination signal is sent.
			mCondition.wait(lock, [this]() { return !mTasks.empty() || mState == Shutdown; });
			// If termination signal received and queue is empty then exit else continue clearing the queue.
			if (mState == Shutdown && mTasks.empty()) {
				SLOGD << "ThreadPool [" << this << "]: terminate thread";
				return;
			}

			// Get next task in the queue.
			task = mTasks.front();

			// Remove it from the queue.
			mTasks.pop();
		}
		// Execute the task.
		task();
		// Keep this to trigger task destructor out of locked scope
		task = nullptr;
	}
}

} // namespace flexisip