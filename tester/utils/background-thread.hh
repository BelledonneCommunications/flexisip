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

#include "utils/thread/must-finish-thread.hh"

namespace flexisip::tester {

/** A thin `std::thread` wrapper designed to take in a long-running `Callable`. When destructed, instances of this class
 * will notify their thread, then ⚠️ wait for it to stop ⚠️.
 *
 * The passed Callable MUST regularly check the `std::atomic_bool` passed to it as its sole argument and MUST stop all
 * processing when it evaluates to `false`. Failure to do so will result in a deadlock at destruction time.
 */
class BackgroundThread {
public:
	template <typename F>
	BackgroundThread(F&& f)
	    : mThread(std::thread([f = std::forward<F>(f), &running = mRunning]() { return f(running); })) {
	}
	~BackgroundThread() {
		mRunning = false;
	}

private:
	std::atomic_bool mRunning = true;
	MustFinishThread mThread;
};

} // namespace flexisip::tester
