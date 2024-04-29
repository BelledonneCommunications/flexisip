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

#pragma once

#include <chrono>
#include <functional>
#include <memory>

#include <sofia-sip/su_wait.h>

namespace sofiasip {

class SuRoot;

/**
 * @brief Helping class for manipulating SofiaSip's timers.
 */
class Timer {
public:
	/**
	 * @brief Callbacks that is called when the timer expires.
	 */
	using Func = std::function<void()>;
	using NativeDuration = std::chrono::duration<su_duration_t, std::milli>;

	/**
	 * @brief Create a timer.
	 * @param[in] root SofiaSip's event loop.
	 * @param[in] intervalMs Default timer expiration interval in milliseconds.
	 * @throw std::logic_error if the timer couldn't been created.
	 */
	explicit Timer(su_root_t* root, su_duration_t intervalMs = 0);

	Timer(su_root_t* root, NativeDuration interval) : Timer{root, interval.count()} {};
	Timer(const sofiasip::SuRoot& root, NativeDuration interval);

	explicit Timer(const std::shared_ptr<sofiasip::SuRoot>& root, su_duration_t intervalMs = 0);

	Timer(const std::shared_ptr<sofiasip::SuRoot>& root, NativeDuration interval);

	~Timer();

	/**
	 * Copying or moving a timer has no sense.
	 */
	Timer(const Timer&) = delete;
	Timer(Timer&&) = delete;

	/**
	 * @brief Start the timer with the default expiration time.
	 * @param[in] func The function to call when the timer expires. The
	 * context of the function is copied and automatically destroyed on
	 * timer expiration.
	 * @throw std::logic_error if the time couldn't be set.
	 */
	void set(const Func& func);
	/**
	 * @brief Start the timer with a specific expiration time.
	 * @param[in] func The function to call when the timer expires. The
	 * context of the function is copied and automatically destroyed on
	 * timer expiration.
	 * @param[in] intervalMs The expiration time in ms.
	 * @throw std::logic_error if the timer couldn't been set.
	 */
	void set(const Func& func, su_duration_t intervalMs);

	/**
	 * @brief Same as before, but using std::chrono for time interval.
	 */
	void set(const Func& func, NativeDuration interval) {
		set(func, interval.count());
	}
	template <typename Duration>
	void set(const Func& func, Duration interval) {
		set(func, std::chrono::duration_cast<NativeDuration>(interval));
	}
	/**
	 * @brief Start the timer to be executed regularly.
	 * @param[in] func The function to call on each interval
	 * of time. The context of the function is copied and is
	 * only destroyed on reset() call.
	 * @throw std::logic_error if the timer couldn't be stated.
	 */
	void run(const Func& func);
	/**
	 * @brief Same as run() except it doesn't try to catch up missed callbacks.
	 */
	void setForEver(const Func& func);
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
	static void _oneShotTimerCb(su_root_magic_t* magic, su_timer_t* t, su_timer_arg_t* arg) noexcept;
	static void _regularTimerCb(su_root_magic_t* magic, su_timer_t* t, su_timer_arg_t* arg) noexcept;

	::su_timer_t* _timer = nullptr;
	Func _func;
};

} // namespace sofiasip
