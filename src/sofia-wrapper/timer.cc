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

#include <stdexcept>

#include <sofia-sip/su_wait.h>

#include "flexisip/sofia-wrapper/su-root.hh"

#include "flexisip/sofia-wrapper/timer.hh"

using namespace std;

namespace sofiasip {

Timer::Timer(su_root_t* root, su_duration_t intervalMs) {
	_timer = su_timer_create(su_root_task(root), intervalMs);
	if (_timer == nullptr) throw logic_error("fail to instantiate the timer");
}

Timer::Timer(const shared_ptr<sofiasip::SuRoot>& root, su_duration_t intervalMs) : Timer{root->getCPtr(), intervalMs} {
}

Timer::Timer(const shared_ptr<sofiasip::SuRoot>& root, NativeDuration interval)
    : Timer{root->getCPtr(), interval.count()} {
}

Timer::~Timer() {
	su_timer_destroy(_timer);
}

void Timer::set(const Func& func) {
	if (su_timer_set(_timer, _oneShotTimerCb, this) != 0) {
		throw logic_error("fail to set timer");
	}
	_func = func;
}

void Timer::set(const Func& func, su_duration_t intervalMs) {
	if (su_timer_set_interval(_timer, _oneShotTimerCb, this, intervalMs) != 0) {
		throw logic_error("fail to set timer");
	}
	_func = func;
}

void Timer::run(const Func &func) {
	if (su_timer_run(_timer, _regularTimerCb, this) != 0) {
		throw logic_error("fail to run timer");
	}
	_func = func;
}

void Timer::setForEver(const Func &func) {
	if (su_timer_set_for_ever(_timer, _regularTimerCb, this) != 0) {
		throw logic_error("fail to set timer");
	}
	_func = func;
}

void Timer::reset() {
	if (su_timer_reset(_timer) != 0) {
		throw logic_error("fail to reset timer");
	}
	_func = nullptr;
}

bool Timer::isRunning() const {
	return su_timer_is_running(_timer) != 0;
}

void Timer::_oneShotTimerCb([[maybe_unused]] su_root_magic_t *magic, [[maybe_unused]] su_timer_t *t, su_timer_arg_t *arg) noexcept {
	auto *timer = static_cast<Timer *>(arg);

	// timer->_func must be emptied before calling the function to avoid
	// invalid Timer state should the function call Timer::set() again.
	// That would result to have the C timer set without C++ function set.
	Func func;
	func.swap(timer->_func);
	func();
}

void Timer::_regularTimerCb([[maybe_unused]] su_root_magic_t* magic, [[maybe_unused]] su_timer_t* t, su_timer_arg_t* arg) noexcept {
	auto* timer = static_cast<Timer*>(arg);
	timer->_func();
}

}
