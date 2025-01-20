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

#include <thread>

namespace flexisip {

/**
 * A thread that MUST finish executing before releasing the handle.
 * (E.g. because it captures refs to resources that are about to be freed.)
 *
 * This wrapper joins the thread on destruction and reassignment.
 * (That is: it blocks the current thread until the wrapped thread has finished executing)
 */
class MustFinishThread {
public:
	MustFinishThread() {
	}
	explicit MustFinishThread(std::thread&& t) : mThread(std::move(t)) {
	}
	~MustFinishThread() {
		finish();
	}

	MustFinishThread& operator=(std::thread&& t) {
		finish();
		mThread = std::move(t);
		return *this;
	}

private:
	std::thread mThread;

	void finish() {
		if (mThread.joinable()) {
			mThread.join();
		}
	}
};

} // namespace flexisip