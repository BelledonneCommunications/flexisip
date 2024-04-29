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

#include <queue>

#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/sofia-wrapper/timer.hh"

namespace flexisip {

/**
 * Can be used for e.g., request throttling/rate limiting.
 * It utilizes the Sofia loop to schedule tasks at a given interval rate.
 *
 * Warning: Utilizing the Sofia loop means that if the specified interval is less than one Sofia loop execution, the
 * rate will be constrained to one Sofia loop execution time.
 */
template <typename Task>
class ConstantRateTaskQueue {
public:
	/**
	 * Constructs a ConstantRateTaskQueue object.
	 *
	 * @param borrowedRoot Reference to the Sofia SIP loop.
	 * @param interval The interval at which tasks are scheduled. If 0, every enqueued task will be executed
	 * syncrhonosly.
	 * @param consumer The function that will consume every task.
	 */
	ConstantRateTaskQueue(sofiasip::SuRoot& borrowedRoot,
	                      sofiasip::Timer::NativeDuration interval,
	                      std::function<void(Task&)> consumer)
	    : mRoot(borrowedRoot), mConsumer(std::move(consumer)), mQueue(), mInterval(interval),
	      mTimer(borrowedRoot, interval) {
	}

	/**
	 * Adds a task to the queue.
	 *
	 * If the timer is not already launched, it runs the first task and starts the timer to run subsequent tasks after
	 * the desired interval.
	 *
	 * If the interval is 0, the task is only run synchronously.
	 */
	void enqueue(Task&& task) {
		if (mInterval == std::chrono::milliseconds{0}) {
			mConsumer(task);
			return;
		}
		if (mQueue.empty() && !mTimer.isRunning()) {
			mConsumer(task);
			startTimer();
			return;
		}
		mQueue.push(std::forward<Task>(task));
	}

	bool empty() const {
		return mQueue.empty();
	}

private:
	void startTimer() {
		mTimer.setForEver([this]() {
			if (mQueue.empty()) {
				mTimer.reset();
				return;
			}

			mConsumer(mQueue.front());
			mQueue.pop();
		});
	}

	sofiasip::SuRoot& mRoot;
	std::function<void(Task&)> mConsumer;
	std::queue<Task> mQueue;
	sofiasip::Timer::NativeDuration mInterval;
	sofiasip::Timer mTimer;
};

} // namespace flexisip
