/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <functional>
#include <memory>

#include <sofia-sip/su_wait.h>

namespace sofiasip {

/**
 * Wraps a sofia wait register to unregister it on destruction
 */
class Waker {
public:
	using Callback = std::function<int(su_root_magic_t*, su_wait_t*)>;

	/** SAFETY:
	 *  - `root` MUST NOT be null and MUST be valid for the lifetime of the Waker
	 */
	Waker(su_root_t* root, int fileDescriptor, Callback&& callback, int priority)
	    : mCallback(std::move(callback)), mRoot(root) {
		su_wait_create(&mWait, fileDescriptor, SU_WAIT_IN);
		su_root_register(
		    mRoot, &mWait,
		    [](su_root_magic_t* root, su_wait_t* wait, su_wakeup_arg_t* arg) noexcept {
			    auto& lambda = *static_cast<Callback*>(arg);
			    return lambda(root, wait);
		    },
		    &mCallback, priority);
	}
	~Waker() {
		su_root_unregister(mRoot, &mWait, nullptr, &mCallback);
	}

	Waker(const Waker& other) = delete;
	Waker& operator=(const Waker& other) = delete;
	Waker(Waker&& other) = delete;
	Waker& operator=(Waker&& other) = delete;

private:
	Callback mCallback;
	su_root_t* mRoot; // borrow
	su_wait_t mWait{0};
};

} // namespace sofiasip
