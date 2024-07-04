/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

#include "compat/hiredis/async.h"
#include "sofia-sip/su_wait.h"

#include "flexisip/logmanager.hh"

#include "redis-args-packer.hh"
#include "redis-auth.hh"
#include "redis-reply.hh"
#include "utils/soft-ptr.hh"
#include "utils/stl-backports.hh"

namespace flexisip::redis::async {

using Reply = reply::Reply;

// The interface you must implement if you want to be notified of connection and disconnection events on a Redis session
class SessionListener {
public:
	virtual ~SessionListener() = default;

	virtual void onConnect([[maybe_unused]] int status) {
	}
	virtual void onDisconnect([[maybe_unused]] int status) {
	}
};

class SubscriptionSession;

/**
 * A connection to Redis with which you can send "regular" commands (as opposed to subscriptions commands, which you
 * must send with a dedicated SubscriptionSession).
 *
 * This class exposes a type-safe interface, allowing you to send commands only when it is in a Ready state.
 *
 * A Session starts in the `Disconnected` state, and you must call `connect()` a first time to start the connection
 * process.
 *
 * At any time, you may call `disconnect()` to gracefully disconnect (wait for current commands to be replied to then
 * close the connection), or forcefully set the state to `Disconnected()` to abort all pending commands and destroy the
 * connection immediately.
 */
class Session final {
	// Sealed with `final` to prevent footgun access to attributes being freed in the `onDisconnect` callback
public:
	// Intelligently free a raw redisAsyncContext* when hiredis would otherwise leak it.
	// (There are cases where hiredis frees the context itself, in which case this deleter does nothing)
	struct ContextDeleter {
		void operator()(redisAsyncContext*) noexcept;
	};
	using ContextPtr = std::unique_ptr<redisAsyncContext, ContextDeleter>;

	using CommandCallback = stl_backports::move_only_function<void(Session&, Reply)>;

	// This session is not connected. You must call `connect()` before being able to do anything with it.
	class Disconnected {
		friend std::ostream& operator<<(std::ostream&, const Disconnected&);
	};

	// This session is ready to send commands.
	// It may not have finished connecting (which you can check with the `connected()` method) but you can already start
	// sending commands. If the connection fails establishing, all pending commands will be aborted (with
	// `reply::Disconnected()`), and the state will switch back to `Disconnected`.
	class Ready {
	public:
		friend class Session;
		friend std::ostream& operator<<(std::ostream&, const Ready&);
		friend class SubscriptionSession;

		// Send an AUTH command
		// https://redis.io/commands/auth/
		void auth(std::variant<auth::ACL, auth::Legacy>, CommandCallback&& callback) const;
		// Send any kind of command, except subscription-related commands (for which you should use a
		// SusbscriptionSession).
		// The `callback` will be called exactly once, with the reply from the Redis server (or `reply::Disconnected` if
		// the session was forcefully disconnected before the command received a reply)
		void command(const ArgsPacker& args, CommandCallback&& callback) const;

		// Wrapper to the `command()` method that will log the wall-clock time the server took to send the reply
		template <typename TCallback>
		void timedCommand(const ArgsPacker& args, TCallback&& callback) const {
			using namespace std::chrono_literals;

			command(args, [cmdString = args.toString(), callback = std::forward<TCallback>(callback),
			               started = std::chrono::system_clock::now()](auto& session, Reply reply) mutable {
				const auto wallClockTime = std::chrono::system_clock::now() - started;
				if (!std::holds_alternative<reply::Disconnected>(reply)) {
					(wallClockTime < 1s ? SLOGD : SLOGW)
					    << "Redis command completed in "
					    << std::chrono::duration_cast<std::chrono::milliseconds>(wallClockTime).count()
					    << "ms (wall-clock time):\n\t" << cmdString;
				}

				callback(session, std::move(reply));
			});
		}

		bool connected() const {
			return mCtx->c.flags & REDIS_CONNECTED;
		}

	private:
		explicit Ready(ContextPtr&&);

		// Possible error cases: Out of Memory, context disconnecting or freeing, UNSUBSCRIBE called on a context that
		// is not subscribed
		[[nodiscard]] int command(const ArgsPacker&, void* cbData, redisCallbackFn* callback) const;

		ContextPtr mCtx;
	};

	// This session is asynchronously disconnecting. It is still connected to Redis and will wait for a reply to all
	// pending commands before automatically switching to the `Disconnected` state. You cannot send new commands in this
	// state.
	class Disconnecting {
		friend std::ostream& operator<<(std::ostream&, const Disconnecting&);
		friend Session;

	private:
		explicit Disconnecting(Ready&&);

		void disconnect();

		ContextPtr mCtx;
	};

	using State = std::variant<Disconnected, Ready, Disconnecting>;

	Session(SoftPtr<SessionListener>&& = {});

	const State& getState() const;
	// Shortcut to `std::get_if<T>(&session.getState())`.
	// Will return nullptr if the session is not in the desired state.
	template <typename T>
	const T* tryGetState() const {
		return std::get_if<T>(&mState);
	}
	// Initiate the connection to Redis. If successful, the returned state will be `Ready`, otherwise the session is
	// left in its current state. The `onConnect` method will be called on the listener when that process finishes and
	// the `.isConnected()` method will start returning `true`. You can immediately start sending commands, but if the
	// connection fails to establish, those will be aborted.
	const State& connect(su_root_t*, const std::string_view& address, int port);
	// Gracefully disconnect.
	// This is an asynchronous process and may take an unbounded amount of iterations of the event loop. Immediately
	// following a call to this method, a Session will be left in either a `Disconnecting` or `Disconnected` state.
	const State& disconnect();
	// Forcefully set the current state to Disconnected, immediately aborting all commands and freeing all callbacks,
	// if any.
	void forceDisconnect();

	// Is this Session ready *and* connected to Redis
	bool isConnected() const;

	// An optional listener to be notified when the context connects and/or disconnects.
	// It is safe to get/set at any time.
	SoftPtr<SessionListener> mListener{};

private:
	void onConnect(const redisAsyncContext*, int status);
	void onDisconnect(const redisAsyncContext*, int status);

	std::string mLogPrefix{};
	// Must be the last member of self, to be destructed first. Destructing the ContextPtr calls onDisconnect
	// synchronously, which still needs access to the rest of self.
	State mState{Disconnected()};
};

/**
 * A connection to Redis dedicated to subscription-related commands.
 *
 * This class exposes a type-safe interface with the same mechanics as that of a "regular" `Session` but with an API
 * tailored to subscriptions.
 *
 * Subscriptions are automatically resumed when reconnecting.
 * I.e: If you subscribe a callback to a topic with an instance of this class, but it gets disconnected (either by you,
 * or by the remote server), then reconnecting that same instance will automatically submit the SUBSCRIBE command again.
 */
class SubscriptionSession final : SessionListener {
	// From https://redis.io/commands/subscribe/
	// "Once the client enters the subscribed state it is not supposed to issue any other commands, except for
	// additional SUBSCRIBE, SSUBSCRIBE, PSUBSCRIBE, UNSUBSCRIBE, SUNSUBSCRIBE, PUNSUBSCRIBE, PING, RESET and QUIT
	// commands"
private:
	struct Subscription;
	// An std::map<> has the guarantee that iterators remain valid after both `.insert()` and `.erase()` operations.
	// Meaning it's safe to keep pointers to its elements in long-lived subscription callbacks
	using SubsMap = std::map<std::string, Subscription>;

public:
	using SubscriptionCallback = std::function<void(std::string_view, Reply)>;

	class Subscriptions;

	// An existing, or hypothetical subscription to a given topic.
	// You can check if this topic is currently subscribed with `.subscribed()`
	class SubscriptionEntry {
	public:
		friend class SubscriptionSession;

		// Prevent dangling references
		SubscriptionEntry(const SubscriptionEntry&) = delete;
		SubscriptionEntry(SubscriptionEntry&&) = delete;

		/**
		 * Send the SUBSCRIBE command to Redis, and register a callback function.
		 * Contrary to "regular" command callbacks, subscription callbacks will be called every time a matching PUBLISH
		 * is issued on the server. Additionally, these callbacks will also be called in the following cases:
		 * - To confirm subscription,
		 * - to confirm unsubscription,
		 * - and whenever the session disconnects.
		 * See https://redis.io/docs/interact/pubsub/
		 *
		 * If there is no subscription yet, this will create it. If there is an existing subscription, the existing
		 * callback is immediately freed without being called and replaced with the new callback. The SUBSCRIBE command
		 * will be issued in *both* cases.
		 *
		 * @param callback May receive
		 * - An `Array` with 3 elements in the following order:
		 *   1. The kind of message (`String`: "subscribe", "unsubscribe", or "message")
		 *   2. The subscription channel name (`String`)
		 *   3. Either
		 *       - The message payload (`String`), or
		 *       - this session's current count of subscriptions (`Integer`),
		 *      depending on the message kind (as per Redis' documentation).
		 * - A `Disconnected` reply when the session disconnects.
		 * Anything outside of that specification is unexpected, but remains **the responsibility of this callback** to
		 * deal with.
		 */
		void subscribe(SubscriptionCallback&& callback);
		// Send the UNSUBSCRIBE command to Redis.
		// This function does not take a callback as it is the callback already registered at subscription that will be
		// called once the server acknowledges the unsubscription. If the session is not subscribed to this topic, this
		// method is a noop, and will *not* send the UNSUBSCRIBE command.
		void unsubscribe();

		// Whether this session is subscribed to this topic.
		bool subscribed() const;
		bool isFresh() const;

	private:
		SubscriptionEntry(const Session::Ready&, SubsMap&, const std::string_view&);

		bool isInMap() const;

		const Session::Ready& mSession;
		SubsMap& mMap;
		std::string mChannel;
		SubsMap::iterator mSlot;
	};

	// A map-like API to the subscriptions of this session.
	class Subscriptions {
	public:
		friend class SubscriptionSession;

		// Prevent dangling references
		Subscriptions(const Subscription&) = delete;
		Subscriptions(Subscription&&) = delete;

		SubscriptionEntry operator[](const std::string_view& topic);

		SubsMap::size_type size() const;

	private:
		Subscriptions(const Session::Ready&, SubsMap&);

		const Session::Ready& mSession;
		SubsMap& mMap;
	};

	// Semantically equivalent to Session::Ready, but exposes an API dedicated to subscriptions
	class Ready {
	public:
		// Send an AUTH command
		// https://redis.io/commands/auth/
		void auth(std::variant<auth::ACL, auth::Legacy>, Session::CommandCallback&& callback) const;
		// Get a view into this session's subscriptions. This is the only way to add or remove subscriptions
		Subscriptions subscriptions() const;

	private:
		Session::Ready mWrapped;
	};
	static_assert(sizeof(Ready) == sizeof(Session::Ready), "Must be reinterpret_cast-able");

	using State = std::variant<Session::Disconnected, Ready, Session::Disconnecting>;

	SubscriptionSession(SoftPtr<SessionListener>&& = {});

	template <typename T>
	const T* tryGetState() const {
		static_assert(!std::is_same_v<T, Session::Ready>,
		              "Can't let you get a regular session interface from a subscriptions session.");
		if constexpr (std::is_same_v<T, Ready>) {
			return reinterpret_cast<const Ready*>(mWrapped.tryGetState<Session::Ready>());
		} else {
			return mWrapped.tryGetState<T>();
		}
	}
	const State& connect(su_root_t* sofiaRoot, const std::string_view& address, int port) {
		return reinterpret_cast<const State&>(mWrapped.connect(sofiaRoot, address, port));
	}
	const State& disconnect() {
		return reinterpret_cast<const State&>(mWrapped.disconnect());
	}
	void forceDisconnect() {
		return mWrapped.forceDisconnect();
	}

	bool isConnected() const;
	const State& getState() const;

	SoftPtr<SessionListener> mListener{};

private:
	struct Subscription {
		SubscriptionCallback callback;
		// This flag prevents sending duplicated SUBSCRIBEs when commands have been issued prior to `onConnect()` being
		// triggered
		bool fresh;
		// This flag is a way to safely handle the asynchronicity of an unsbuscribe process.
		// (We must handle the acknowledgement response from Redis before we can free the subscription)
		bool unsubbed;
	};

	void onConnect(int status) override;
	void onDisconnect(int status) override;

	static auto& getSubscriptionsFrom(const redisAsyncContext* rawContext);

	SubsMap mSubscriptions{};
	Session mWrapped;
};

} // namespace flexisip::redis::async
