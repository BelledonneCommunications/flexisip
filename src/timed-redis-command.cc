/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "timed-redis-command.hh"

#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <memory>
#include <string>

#include "compat/hiredis/async.h"

#include "registrardb-redis.hh"

using namespace std::chrono_literals;

namespace flexisip::redis {

namespace {
std::string string_format(const char* format, std::va_list args) {
	std::va_list argsCopy;
	va_copy(argsCopy, args);
	int size_s = std::vsnprintf(nullptr, 0, format, args) + 1; // Extra space for '\0'
	va_end(args);
	if (size_s <= 0) {
		return "<Error during formatting>";
	}
	auto size = static_cast<size_t>(size_s);
	auto formatted = std::string(size, '\0');
	std::vsnprintf(formatted.data(), size, format, argsCopy);
	va_end(argsCopy);
	return formatted;
}

} // namespace

RedisCommandTimer::TimedRedisCommand::TimedRedisCommand(redisCallbackFn* callback, void* data, std::string&& command)
    : mCallback(callback), mData(data), mCommand(std::move(command)), mStarted(std::chrono::system_clock::now()) {
}

int RedisCommandTimer::send(
    redisAsyncContext* redisContext, redisCallbackFn* callback, void* data, const char* format, ...) {
	std::va_list varArgs;
	va_start(varArgs, format);
	std::va_list forwarded;
	va_copy(forwarded, varArgs);
	auto* context =
	    mPendingCommands.emplace_back(new TimedRedisCommand(callback, data, string_format(format, varArgs))).get();
	va_end(varArgs);

	int status = redisvAsyncCommand(redisContext, sLogTimeAndCallWrapped, context, format, forwarded);
	va_end(forwarded);
	if (status != REDIS_OK) {
		mPendingCommands.pop_back();
	}

	return status;
}

int RedisCommandTimer::send(redisAsyncContext* redisContext,
                            redisCallbackFn* callback,
                            void* data,
                            RedisArgsPacker& args) {
	auto* context = mPendingCommands.emplace_back(new TimedRedisCommand(callback, data, args.toString())).get();

	int status = redisAsyncCommandArgv(redisContext, sLogTimeAndCallWrapped, context, args.getArgCount(),
	                                   args.getCArgs(), args.getArgSizes());
	if (status != REDIS_OK) {
		mPendingCommands.pop_back();
	}

	return status;
}

void RedisCommandTimer::sLogTimeAndCallWrapped(redisAsyncContext* redisContext, void* reply, void* contextPtr) {
	const auto* context = static_cast<TimedRedisCommand*>(contextPtr);
	const auto wallClockTime = std::chrono::system_clock::now() - context->mStarted;
	(wallClockTime < 1s ? SLOGD : SLOGW) << "Redis command completed in "
	                                     << std::chrono::duration_cast<std::chrono::milliseconds>(wallClockTime).count()
	                                     << "ms (wall-clock time):\n\t" << context->mCommand;

	if (auto* callback = context->mCallback) {
		callback(redisContext, reply, context->mData);
	}
	static_cast<RegistrarDbRedisAsync*>(redisContext->data)->mTimedCommand.commandFinished(context);
}

void RedisCommandTimer::commandFinished(const TimedRedisCommand* finished) {
	for (auto iterator = mPendingCommands.begin(); iterator != mPendingCommands.end(); iterator++) {
		if (iterator->get() == finished) {
			mPendingCommands.erase(iterator);
			return;
		}
	}
}

} // namespace flexisip::redis
