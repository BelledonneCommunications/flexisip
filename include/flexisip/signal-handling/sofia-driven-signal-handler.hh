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

#include <functional>

#include "flexisip/logmanager.hh"
#include "flexisip/signal-handling/signal-handling.hh"
#include "flexisip/sofia-wrapper/waker.hh"

namespace flexisip::signal_handling {

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
			          SLOGE << "Error on signal pipe";
			          return 0;
		          }
		          if (waiter->revents & SU_WAIT_HUP) {
			          SLOGE << "Signal pipe closed";
			          return 0;
		          }

		          SignalData signal;
		          if (mSignalPipe.read(signal) != sizeof(signal)) {
			          SLOGE << "Error reading from signal pipe";
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

} // namespace flexisip::signal_handling