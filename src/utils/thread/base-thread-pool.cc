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

#include "flexisip/logmanager.hh"

#include "base-thread-pool.hh"

using namespace std;

namespace flexisip {

bool BaseThreadPool::run(Task t) {
	bool enqueued = false;
	// Scope based locking.
	{
		// Put unique lock on task mutex.
		unique_lock<mutex> lock(mTasksMutex);

		// Push task into queue.
		if (mMaxQueueSize == 0 || mTasks.size() < mMaxQueueSize) {
			mTasks.push(t);
			enqueued = true;
		}
	}

	// Wake up one thread if the task was successfully queued
	if (enqueued) {
		mCondition.notify_one();
	}

	return enqueued;
}

} // namespace flexisip
