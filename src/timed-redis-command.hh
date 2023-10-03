/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "compat/hiredis/async.h"

namespace flexisip {

class RedisArgsPacker;

namespace redis {

// Logs the real-world time taken by a Redis command to return.
// Do __not__ use with callbacks that can be called more than once.
class RedisCommandTimer {
public:
	RedisCommandTimer() = default;

	int send(redisAsyncContext* asyncContext, redisCallbackFn* callback, void* data, const char* format, ...);
	int send(redisAsyncContext* asyncContext, redisCallbackFn* callback, void* data, RedisArgsPacker& args);

private:
	class TimedRedisCommand {
	public:
		friend class RedisCommandTimer;

	private:
		static void sLogTimeAndCallWrapped(redisAsyncContext* redisContext, void* reply, void* contextPtr);

		TimedRedisCommand(redisCallbackFn*, void*, std::string&&);
		redisCallbackFn* mCallback;
		void* mData;
		const std::string mCommand;
		const std::chrono::time_point<std::chrono::system_clock> mStarted;
	};

	static void sLogTimeAndCallWrapped(redisAsyncContext* redisContext, void* reply, void* contextPtr);

	void commandFinished(const TimedRedisCommand*);

	std::vector<std::unique_ptr<TimedRedisCommand>> mPendingCommands{};
};

} // namespace redis
} // namespace flexisip
