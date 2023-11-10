/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL.

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

#pragma once

#include <chrono>
#include <functional>
#include <list>
#include <stdexcept>

#include "flexisip/sofia-wrapper/timer.hh"

namespace sofiasip {

class SuRoot {
public:
	using NativeDuration = std::chrono::duration<su_duration_t, std::milli>;

	SuRoot() : mCPtr{su_root_create(nullptr)} {
		if (mCPtr == nullptr) {
			throw std::runtime_error{"su_root_t allocation failed"};
		}
	}
	SuRoot(const SuRoot&) = delete;
	~SuRoot() {
		// Clear the list first because su_root_destroy free all timers, and lead to
		// heap-use-after-free if done before the list destruction.
		mOneShotTimerList.clear();
		su_root_destroy(mCPtr);
	}

	su_root_t* getCPtr() const noexcept {
		return mCPtr;
	}

	template <typename Duration>
	auto step(Duration timeout) {
		return static_cast<NativeDuration>(
		    su_root_step(mCPtr, std::chrono::duration_cast<NativeDuration>(timeout).count()));
	}

	template <typename Duration>
	auto sleep(Duration duration) {
		return static_cast<NativeDuration>(
		    su_root_sleep(mCPtr, std::chrono::duration_cast<NativeDuration>(duration).count()));
	}

	void run() {
		su_root_run(mCPtr);
	}
	void quit() {
		su_root_break(mCPtr);
	}
	_su_task_r getTask() const {
		return su_root_task(mCPtr);
	}

	void addToMainLoop(const std::function<void()>& functionToAdd);
	void addOneShotTimer(const std::function<void()>& timerFunction, NativeDuration ms);
	template <typename Duration>
	void addOneShotTimer(const std::function<void()>& timerFunction, Duration ms) {
		addOneShotTimer(timerFunction, std::chrono::duration_cast<NativeDuration>(ms));
	}

private:
	static void mainLoopFunctionCallback(su_root_magic_t* rm, su_msg_r msg, void* u) noexcept;
	static void mainLoopFunctionCallbackDeinitializer(su_msg_arg_t* data) noexcept;

	::su_root_t* mCPtr{nullptr};
	std::list<sofiasip::Timer> mOneShotTimerList{};
};

} // namespace sofiasip
