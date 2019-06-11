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


#include "flexisip/logmanager.hh"

#include "threadpool.hh"

using namespace std;

namespace flexisip {

ThreadPool::ThreadPool(unsigned int nThreads, unsigned int maxQueueSize) : mMaxQueueSize(maxQueueSize) {
	SLOGD << "ThreadPool [" << this << "]: init with " << nThreads << " threads and queue size " << maxQueueSize;

	// Create number of required threads and add them to the thread pool vector.
	for (unsigned int i = 0; i < nThreads; i++) {
		mThreadPool.emplace_back(&ThreadPool::_run, this);
	}
}

ThreadPool::~ThreadPool() {
	if (mState != Stopped) stop();
}

bool ThreadPool::run(Task t) {
	bool enqueued = false;
	// Scope based locking.
	{
		// Put unique lock on task mutex.
		unique_lock<mutex> lock(mTasksMutex);

		// Push task into queue.
		if (mTasks.size() < mMaxQueueSize) {
			mTasks.push(t);
			enqueued = true;
		}
	}

	// Wake up one thread if the task was successfully queued
	if (enqueued)
		mCondition.notify_one();

	return enqueued;
}

void ThreadPool::stop() {
	SLOGD << "ThreadPool [" << this << "]: shutdown";
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
	for (auto &thread : mThreadPool) {
		thread.join();
	}

	// Empty workers vector.
	mThreadPool.empty();

	// Indicate that the pool has been shut down.
	mState = Stopped;
}

void ThreadPool::_run() {
	Task task;
	while (true) {
		// Scope based locking.
		{
			// Put unique lock on task mutex.
			unique_lock<mutex> lock(mTasksMutex);

			// Wait until queue is not empty or termination signal is sent.
			ThreadPool *thiz = this;
			mCondition.wait(lock, [thiz](){return !thiz->mTasks.empty() || thiz->mState == Shutdown;});

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
	}
}

} // namespace flexisip
