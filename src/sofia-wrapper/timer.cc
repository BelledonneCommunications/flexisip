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

#include <stdexcept>

#include "sofia-sip/su_wait.h"

#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/sofia-wrapper/timer.hh"

using namespace std;

namespace sofiasip {

Timer::Timer(su_root_t* root, su_duration_t intervalMs) {
	mTimer = su_timer_create(su_root_task(root), intervalMs);
	if (mTimer == nullptr) throw logic_error("fail to instantiate the timer");
}

Timer::Timer(const sofiasip::SuRoot& root, NativeDuration intervalMs) : Timer{root.getCPtr(), intervalMs} {
}

Timer::Timer(const shared_ptr<sofiasip::SuRoot>& root, su_duration_t intervalMs) : Timer{root->getCPtr(), intervalMs} {
	mRoot = root;
}

Timer::Timer(const shared_ptr<SuRoot>& root, NativeDuration intervalMs) {
	if (mTimer = su_timer_create(root->getTask(), intervalMs.count()); !mTimer) {
		if (errno == ENOMEM) throw runtime_error("failed to create the timer (out of memory)");
		throw invalid_argument("failed to create the timer");
	}
	mRoot = root;
}

Timer::~Timer() {
	su_timer_destroy(mTimer);
}

void Timer::set(const Func& func) {
	if (su_timer_set(mTimer, _oneShotTimerCb, this) != 0) throw logic_error("failed to set the timer");
	mFunc = func;
	mOneShotTimerHasExpired = false;
}

void Timer::set(const Func& func, su_duration_t intervalMs) {
	if (su_timer_set_interval(mTimer, _oneShotTimerCb, this, intervalMs) != 0)
		throw logic_error("failed to set the timer");
	mFunc = func;
	mOneShotTimerHasExpired = false;
}

void Timer::run(const Func& func) {
	if (su_timer_run(mTimer, _regularTimerCb, this) != 0) throw logic_error("failed to run the timer");
	mFunc = func;
}

void Timer::setForEver(const Func& func) {
	if (su_timer_set_for_ever(mTimer, _regularTimerCb, this) != 0) throw logic_error("failed to set the timer");
	mFunc = func;
}

void Timer::stop() {
	if (su_timer_reset(mTimer) != 0) throw logic_error("failed to stop the timer");
	mFunc = nullptr;
}

bool Timer::isRunning() const {
	return su_timer_is_running(mTimer) != 0;
}

bool Timer::hasAlreadyExpiredOnce() const {
	return mOneShotTimerHasExpired || su_timer_woken(mTimer) != 0;
}

void Timer::_oneShotTimerCb([[maybe_unused]] su_root_magic_t* magic,
                            [[maybe_unused]] su_timer_t* t,
                            su_timer_arg_t* arg) noexcept {
	auto* timer = static_cast<Timer*>(arg);
	timer->mOneShotTimerHasExpired = true;

	// The attribute timer->_func must be emptied before calling the function to avoid an invalid Timer state if the
	// function calls Timer::set() again. That would result in having the C timer set without a C++ function set.
	Func func;
	func.swap(timer->mFunc);
	func();
}

void Timer::_regularTimerCb([[maybe_unused]] su_root_magic_t* magic,
                            [[maybe_unused]] su_timer_t* t,
                            su_timer_arg_t* arg) noexcept {
	auto* timer = static_cast<Timer*>(arg);
	timer->mFunc();
}

} // namespace sofiasip