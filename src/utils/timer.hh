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

#pragma once

#include <functional>

#include <sofia-sip/su_wait.h>

namespace sofiasip {

/**
 * @brief Helping class for manipulating SofiaSip's timers.
 */
class Timer {
public:
	/**
	 * @brief Callbacks that is called when the timer expires.
	 */
	using Func = std::function<void()>;

	/**
	 * @brief Create a timer.
	 * @param[in] root SofiaSip's event loop.
	 * @param[in] intervalMs Default timer expiration inteval in miliseconds.
	 * @throw std::logic_error if the timer couldn't been created.
	 */
	Timer(su_root_t *root, unsigned intervalMs = 0);
	~Timer();

	/**
	 * @brief Start the timer with the default expiration time.
	 * @param[in] func The funciton to call when the timer expires.
	 * @throw std::logic_error if the time couldn't be set.
	 */
	void set(const Func &func);
	/**
	 * @brief Start the timer with a specific expiration time.
	 * @param[in] func The funciton to call when the timer expires.
	 * @param[in] intervalMs The expiration time in ms.
	 * @throw std::logic_error if the timer couldn't been set.
	 */
	void set(const Func &func, unsigned intervalMs);
	/**
	 * @brief Stop the timer and delete the internal function.
	 * @throw std::logic_error if the timer couldn't been reset.
	 */
	void reset();
	/**
	 * @brief Check whether the timer has already been set.
	 */
	bool isRunning() const;

private:
	static void _internalCb(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) noexcept;

	::su_timer_t *_timer = nullptr;
	Func _func;
};

}
