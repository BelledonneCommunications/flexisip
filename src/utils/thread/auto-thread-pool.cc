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

#include "auto-thread-pool.hh"

#include "flexisip/configmanager.hh"
#include "flexisip/logmanager.hh"

using namespace std;

namespace flexisip {

std::unique_ptr<AutoThreadPool> AutoThreadPool::sDbThreadPool{};

std::unique_ptr<AutoThreadPool>& AutoThreadPool::getDbThreadPool(unsigned int maxThreadNumber) {
	if (!sDbThreadPool) {
		sDbThreadPool = std::make_unique<AutoThreadPool>(maxThreadNumber, 0);
	}

	return sDbThreadPool;
}

AutoThreadPool::AutoThreadPool(unsigned int maxThreadNumber, unsigned int maxQueueSize)
    : BaseThreadPool(maxQueueSize, maxThreadNumber),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "AutoThreadPool")) {
	LOGD << "Init with " << maxThreadNumber << " threads and queue size " << maxQueueSize;

	// Run the thread that will start every other thread
	mainThread = make_unique<thread>(&AutoThreadPool::_run, this);
}

AutoThreadPool::~AutoThreadPool() {
	if (mState != Stopped) stop();
}

void AutoThreadPool::stop() {
	LOGD << "Shutdown";
	// Scope based locking.
	{
		// Put unique lock on task mutex.
		unique_lock<mutex> lock(mTasksMutex);

		// Set termination flag to true.
		mState = Shutdown;
	}

	// Wake up main thread.
	mCondition.notify_one();

	// Join all threads.
	mainThread->join();

	// Indicate that the pool has been shut down.
	mState = Stopped;
}

void AutoThreadPool::_run() {
	Task task;
	while (true) {
		{ // Scope based locking.
			// Put unique lock on task mutex.
			unique_lock<mutex> lock(mTasksMutex);

			// Wait until queue is not empty or termination signal is sent, respecting max thread count.
			mCondition.wait(lock, [this]() {
				if (mCurrentThreadNumber == mMaxThreadNumber) {
					LOGD_CTX(mLogPrefix, "run") << "Notified but max thread number is reached";
				}
				return (!mTasks.empty() && mCurrentThreadNumber < mMaxThreadNumber) ||
				       (mCurrentThreadNumber < mMaxThreadNumber && mState == Shutdown);
			});

			// If termination signal received and queue is empty then exit else continue clearing the queue.
			if (mTasks.empty() && mState == Shutdown) {
				LOGD << "Terminate threads";
				mCondition.wait(lock, [this]() { return mCurrentThreadNumber == 0; });
				return;
			}

			// Get next task in the queue.
			task = mTasks.front();

			try {
				// launch the task on a new thread
				thread taskRunner{&AutoThreadPool::_subThreadRun, this, task};
				taskRunner.detach();
				mCurrentThreadNumber++;

				// Remove task from the queue.
				mTasks.pop();
			} catch (const system_error& e) {
				LOGE << "Error while creating new thread (n°" << mCurrentThreadNumber << "), with error: " << e.what();
				lock.unlock();

				// Hard wait to allow task thread to run before new task thread creation
				this_thread::sleep_for(1s);
			}
		} // End of scope based locking.

		// Keep this to trigger task destructor out of locked scope
		task = nullptr;
	}
}

void AutoThreadPool::_subThreadRun(Task initialTask) {
	initialTask();
	while (true) {
		Task moreTask;
		{ // Scope based locking.
			lock_guard<mutex> lock{mTasksMutex};
			if (mTasks.empty()) {
				break;
			}
			moreTask = mTasks.front();
			mTasks.pop();
		} // End of scope based locking.
		moreTask();
		// Keep this to trigger task destructor out of locked scope
		moreTask = nullptr;
	}
	mCurrentThreadNumber--;
	mCondition.notify_one();
}

} // namespace flexisip