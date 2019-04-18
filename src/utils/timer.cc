/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010  Belledonne Communications SARL.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdexcept>

#include <sofia-sip/su_wait.h>

#include "timer.hh"

using namespace std;

namespace sofiasip {

Timer::Timer(su_root_t *root, unsigned intervalMs) {
	_timer = su_timer_create(su_root_task(root), intervalMs);
	if (_timer == nullptr) throw logic_error("fail to instantiate the timer");
}

Timer::~Timer() {
	su_timer_destroy(_timer);
}

void Timer::set(const Func &func) {
	if (su_timer_set(_timer, _internalCb, this) != 0) {
		throw logic_error("fail to set timer");
	}
	_func = func;
}

void Timer::set(const Func &func, unsigned intervalMs) {
	if (su_timer_set_interval(_timer, _internalCb, this, intervalMs) != 0) {
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

void Timer::_internalCb(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) noexcept {
	auto *timer = static_cast<Timer *>(arg);

	// timer->_func must be emptied before calling the function to avoid
	// invalid Timer state should the function call Timer::set() again.
	// That would result to have the C timer set without C++ function set.
	Func func;
	func.swap(timer->_func);
	func();
}

}
