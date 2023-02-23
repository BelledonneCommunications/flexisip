/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <functional>

#include "flexisip/logmanager.hh"
#include "flexisip/signal-handling/signal-handling.hh"
#include "flexisip/sofia-wrapper/waker.hh"

namespace flexisip {

namespace signal_handling {

/**
 * Register a lambda to be called by the sofia loop after the given POSIX signals have been received.
 *
 * This lambda runs outside of the signal action callback and therefore does not need to be signal-safe.
 *
 * On destruction, this object unregisters from the sofia loop and signal handling mechanism.
 *
 * In the event that two handlers are created for the same signal, the one created last will shadow the first (which
 * will therefore never be called again)
 */
class SofiaDrivenSignalHandler {
	using Callback = std::function<void(SigNum)>;

public:
	/** SAFETY:
	 *  - `root` MUST NOT be null and MUST be valid for the lifetime of the Handler
	 */
	SofiaDrivenSignalHandler(su_root_t* root, std::vector<SigNum>&& signals, Callback&& callback)
	    : mSignalPipe(std::move(signals)), mCallback(std::move(callback)),
	      mWaker(
	          root,
	          mSignalPipe.descriptor(),
	          // SAFETY: Capturing `this` is safe because we own the Waker.
	          [this](su_root_magic_t*, su_wait_t* waiter) noexcept {
		          // Logging is safe in here since we're out of the signal handler
		          if (waiter->revents & SU_WAIT_ERR) {
			          LOGE("Error on signal pipe");
			          return 0;
		          }
		          if (waiter->revents & SU_WAIT_HUP) {
			          LOGE("Signal pipe closed");
			          return 0;
		          }

		          SignalData signal;
		          if (mSignalPipe.read(signal) != sizeof(signal)) {
			          LOGE("Error reading from signal pipe");
			          return 0;
		          }

		          mCallback(signal.signum);
		          return 0;
	          },
	          su_pri_normal) {
	}

private:
	PipedSignal mSignalPipe;
	Callback mCallback;
	sofiasip::Waker mWaker;
};

} // namespace signal_handling

} // namespace flexisip
