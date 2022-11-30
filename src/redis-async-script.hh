/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "compat/hiredis/async.h"

using namespace std;

namespace redis {

struct AsyncCommand {
	const char* mFormatStr;

	template <typename... Args>
	void call(redisAsyncContext* context, redisCallbackFn* fn, void* privdata, Args... args) const noexcept {
		const auto redisStatus = redisAsyncCommand(context, fn, privdata, mFormatStr, args...);
		if (redisStatus != REDIS_OK) {
			LOGE("Failed to call async Redis command '%s'. Status: %d", mFormatStr, redisStatus);
		}
	}
};

template <typename... Args>
class PrefilledAsyncCommand {
	using TArgs = tuple<Args...>;

public:
	PrefilledAsyncCommand(AsyncCommand command, Args... args) : mCommand(command), mArgs(make_tuple(args...)) {
	}
	PrefilledAsyncCommand(const char* command, Args... args) : PrefilledAsyncCommand(AsyncCommand{command}, args...) {
	}

	template <size_t... I>
	void call(redisAsyncContext* context, redisCallbackFn* fn, void* privdata, index_sequence<I...>) {
		mCommand.call(context, fn, privdata, get<I>(mArgs)...);
	}

	void call(redisAsyncContext* context, redisCallbackFn* fn, void* privdata) {
		call(context, fn, privdata, make_index_sequence<tuple_size<TArgs>::value>());
	}

private:
	AsyncCommand mCommand;
	TArgs mArgs;
};

template <typename TCallback, typename... Args>
class AsyncScriptHandler {
	using Self = AsyncScriptHandler;

public:
	AsyncScriptHandler(const char* SHA1,
	                   PrefilledAsyncCommand<const char*> loadScriptCmd,
	                   PrefilledAsyncCommand<const char*, Args...> callScriptCmd,
	                   TCallback&& callback)
	    : SHA1(SHA1), loadScriptCmd(loadScriptCmd), callScriptCmd(callScriptCmd), callback(move(callback)) {
	}

	void callScript(redisAsyncContext* context) {
		callScriptCmd.call(context, onCommandReturned, this);
	}

private:
	const char* SHA1;
	PrefilledAsyncCommand<const char*> loadScriptCmd;
	PrefilledAsyncCommand<const char*, Args...> callScriptCmd;
	TCallback callback;

	static void onCommandReturned(redisAsyncContext* context, void* rawReply, void* rawSelf) noexcept {
		auto reply = static_cast<redisReply*>(rawReply);
		auto self = unique_ptr<Self>(static_cast<Self*>(rawSelf));

		switch (reply->type) {
			case REDIS_REPLY_ARRAY: { // Script executed successfully
				self->callback(reply);
			} break;
			case REDIS_REPLY_ERROR: {
				if (strcmp(reply->str, "NOSCRIPT No matching script. Please use EVAL.") == 0) {
					// Script cache is cold. Load script and schedule retry
					self.release()->loadScript(context);
				} else {
					LOGE("%s callback received error reply from Redis: %s", __FUNCTION__, reply->str);
				}
			} break;
			case REDIS_REPLY_STRING: { // Script loaded successfully
				if (strcmp(reply->str, self->SHA1) != 0) {
					LOGE("Fetch expiring contacts script SHA mismatch. Expected %s got %s. If you have changed the Lua "
					     "source code, you should update the SHA.",
					     self->SHA1, reply->str);
				} else {
					// Retry
					self.release()->callScript(context);
				}
			} break;

			default:
				LOGE("%s callback received unexpected reply type %d from Redis.", __FUNCTION__, reply->type);
				break;
		}
	}

	void loadScript(redisAsyncContext* context) {
		loadScriptCmd.call(context, onCommandReturned, this);
	}
};

/**
 * A fluent interface to calling Lua scripts on Redis.
 *
 * The variadic template Args are the script's parameter types.
 *
 * Call the script with `.with()` to fill in the arguments, then follow up with `.then()` to provide a callable to
 * process the script's output, and finish with `.call()` to send the request to Redis.
 */
template <typename... Args>
class AsyncScript {
public:
	template <typename TCallback>
	class Ready {
		friend class AsyncScript;

	public:
		/**
		 * Send the request to Redis
		 */
		void call(redisAsyncContext* context) {
			mHandler.release()->callScript(context);
		}

	private:
		using Handler = AsyncScriptHandler<TCallback, Args...>;

		unique_ptr<Handler> mHandler;

		Ready(const AsyncScript& script,
		      PrefilledAsyncCommand<const char*, Args...>&& callScriptCmd,
		      TCallback&& callback)
		    : mHandler(make_unique<Handler>(script.mSHA1, script.mLoadScriptCmd, move(callScriptCmd), move(callback))) {
		}
	};

	class WithArgs {
		friend class AsyncScript;

	public:
		/**
		 * Provide a callback to process the returned data.
		 *
		 * The callback will outlive this call and be deleted when it has finished executing.
		 * (Or before if an error occurs, and therefore will never execute.)
		 */
		template <typename TCallback>
		Ready<TCallback> then(TCallback&& callback) {
			return Ready<TCallback>(mScript, move(mCallScriptCmd), move(callback));
		}

	private:
		const AsyncScript& mScript;
		PrefilledAsyncCommand<const char*, Args...> mCallScriptCmd;

		WithArgs(const AsyncScript& script, Args... args)
		    : mScript(script), mCallScriptCmd(script.mCallScriptCmd, script.mSHA1, args...) {
		}
	};

	/**
	 * @param source The Lua code to be executed on Redis
	 * @param SHA1 The SHA1 checksum of `source`
	 */
	AsyncScript(const char* source, const char* SHA1)
	    : mSHA1(SHA1), mLoadScriptCmd("SCRIPT LOAD %s", source), mCallScriptCmd{"EVALSHA %s 1 fs:* %d %d"} {
	}

	/**
	 * Start a fluent call by providing the arguments to the script
	 */
	WithArgs with(Args... args) const {
		return WithArgs(*this, args...);
	}

private:
	const char* mSHA1;
	PrefilledAsyncCommand<const char*> mLoadScriptCmd;
	AsyncCommand mCallScriptCmd;
};

} // namespace redis
