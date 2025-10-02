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

#include <chrono>
#include <functional>
#include <memory>

#include "sofia-sip/su_wait.h"

namespace sofiasip {

class SuRoot;

/**
 * @brief Wrapper for SofiaSip's timers.
 */
class Timer {
public:
	/**
	 * @brief Callback that is called when the timer expires.
	 */
	using Func = std::function<void()>;
	using NativeDuration = std::chrono::duration<su_duration_t, std::milli>;

	/**
	 * @brief Create a timer.
	 * @param[in] root SofiaSip's event loop.
	 * @param[in] intervalMs Default timer expiration interval in milliseconds.
	 * @throw std::logic_error if the timer couldn't been created.
	 */
	[[deprecated]] explicit Timer(su_root_t* root, su_duration_t intervalMs = 0);

	[[deprecated]] Timer(su_root_t* root, NativeDuration interval);
	[[deprecated]] Timer(const sofiasip::SuRoot& root, NativeDuration interval);

	[[deprecated]] explicit Timer(const std::shared_ptr<sofiasip::SuRoot>& root, su_duration_t intervalMs = 0);

	explicit Timer(const std::shared_ptr<SuRoot>& root, NativeDuration interval);

	~Timer();

	// Copying or moving a timer has no sense.
	Timer(const Timer&) = delete;
	Timer(Timer&&) = delete;

	/**
	 * @brief Start the timer with the default expiration time.
	 *
	 * @param[in] func The function to call when the timer expires. The context of the function is copied and
	 * automatically destroyed on timer expiration.
	 * @throw std::logic_error if the timer could not be set.
	 */
	void set(const Func& func);
	/**
	 * @brief Start the timer with a specific expiration time.
	 *
	 * @param[in] func The function to call when the timer expires. The context of the function is copied and
	 * automatically destroyed on timer expiration.
	 * @param[in] intervalMs The expiration time in ms.
	 * @throw std::logic_error if the timer could not be set.
	 */
	void set(const Func& func, su_duration_t intervalMs);
	/**
	 * @brief Start the timer with a specific expiration time.
	 *
	 * @param[in] func The function to call when the timer expires. The context of the function is copied and
	 * automatically destroyed on timer expiration.
	 * @param[in] interval The expiration time.
	 * @throw std::logic_error if the timer could not be set.
	 */
	void set(const Func& func, NativeDuration interval) {
		set(func, interval.count());
	}
	/**
	 * @brief Start the timer with a specific expiration time.
	 *
	 * @param[in] func The function to call when the timer expires. The context of the function is copied and
	 * automatically destroyed on timer expiration.
	 * @param[in] interval The expiration time.
	 * @throw std::logic_error if the timer could not be set.
	 */
	template <typename Duration>
	void set(const Func& func, Duration interval) {
		set(func, std::chrono::duration_cast<NativeDuration>(interval));
	}
	/**
	 * @brief Start the timer to be executed regularly.
	 * @warning Use with care as it will be called many times in case of time leap.
	 *
	 * @param[in] func The function to call on each interval of time. The context of the function is copied and is only
	 * destroyed on the stop() call.
	 * @throw std::logic_error if the timer could not be set.
	 */
	void run(const Func& func);
	/**
	 * @brief Start the timer to be executed regularly.
	 * @note Same as run() except it doesn't try to catch up missed callbacks.
	 *
	 * @param[in] func The function to call on each interval of time. The context of the function is copied and is only
	 * destroyed on the stop() call.
	 * @throw std::logic_error if the timer could not be set.
	 */
	void setForEver(const Func& func);
	/**
	 * @brief Stop the timer and delete the internal function.
	 *
	 * @throw std::logic_error if the timer could not be stopped.
	 */
	void stop();
	/**
	 * @return 'true' if the timer is of type 'running' ('run_for_ever' or 'run_at_intervals'), 'false' otherwise.
	 */
	bool isRunning() const;
	/**
	 * @return 'true' if the timer has already expired (callback function executed), 'false' otherwise.
	 */
	bool hasAlreadyExpiredOnce() const;

private:
	static void _oneShotTimerCb(su_root_magic_t* magic, su_timer_t* t, su_timer_arg_t* arg) noexcept;
	static void _regularTimerCb(su_root_magic_t* magic, su_timer_t* t, su_timer_arg_t* arg) noexcept;

	std::shared_ptr<SuRoot> mRoot{};
	su_timer_t* mTimer{};
	Func mFunc;
	bool mOneShotTimerHasExpired{};
};

} // namespace sofiasip