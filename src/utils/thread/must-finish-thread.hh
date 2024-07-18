/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
