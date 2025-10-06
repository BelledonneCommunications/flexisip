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

#include "redis-async-session.hh"

#include <bitset>
#include <cassert>
#include <cstring>
#include <exception>
#include <ios>
#include <memory>
#include <new>
#include <ostream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>

#include "flexisip/logmanager.hh"

#include "compat/hiredis/async.h"
#include "libhiredis-wrapper/async-ctx/factory.hh"
#include "libhiredis-wrapper/redis-args-packer.hh"
#include "libhiredis-wrapper/redis-auth.hh"
#include "libhiredis-wrapper/redis-reply.hh"
#include "registrardb-redis-sofia-event.h"
#include "sofia-sip/su_wait.h"
#include "utils/variant-utils.hh"

using namespace std::string_view_literals;

namespace flexisip::redis::async {

Session::Session(const ConnectionParameters& connectionParams, SoftPtr<SessionListener>&& listener)
    : mListener(std::move(listener)), mLogPrefix(LogManager::makeLogPrefixForInstance(this, "Session")) {
	mAsyncContextCreator = AsyncCtxCreatorFactory::makeAsyncCtxCreator(connectionParams);
}

const Session::State& Session::connect(su_root_t* sofiaRoot, const std::string_view& address, int port) {
	[&]() {
		if (auto* ready = std::get_if<Ready>(&mState)) {
			LOGD_CTX(mLogPrefix, "connect") << "Called on " << *ready << ": noop";
			return;
		}

		if (!mAsyncContextCreator) throw std::runtime_error{"no AsyncContextCreator"};

		AsyncContextPtr ctx = mAsyncContextCreator->createAsyncCtx(address, port);
		if (ctx->err) {
			LOGE_CTX(mLogPrefix, "connect") << "Connection error: " << ctx->err;
			return;
		}

		ctx->data = this;
		int callbackAdded = redisAsyncSetConnectCallback(ctx.get(), [](const redisAsyncContext* ctx, int status) {
			static_cast<Session*>(ctx->data)->onConnect(ctx, status);
		});
		if (callbackAdded == REDIS_ERR) {
			throw std::logic_error{"`onConnect` callback already set on redisAsyncContext struct"};
			// This is impossible: the context has just been created
		}

		callbackAdded = redisAsyncSetDisconnectCallback(ctx.get(), [](const redisAsyncContext* ctx, int status) {
			static_cast<Session*>(ctx->data)->onDisconnect(ctx, status);
		});
		if (callbackAdded == REDIS_ERR) {
			throw std::logic_error{"`onDisconnect` callback already set on redisAsyncContext struct"};
			// This is impossible: the context has just been created
		}

		if (REDIS_OK != redisSofiaAttach(ctx.get(), sofiaRoot)) {
			LOGE_CTX(mLogPrefix, "connect") << "Failed to hook into Sofia loop: " << ::strerror(errno);
			return;
		}

		mState = Ready(std::move(ctx));
		LOGD_CTX(mLogPrefix, "connect") << "Connection initiated to " << address << ":" << port
		                                << ", new state: " << StreamableVariant(mState);
	}();
	return mState;
}
const Session::State& Session::disconnect() {
	mState = Match(std::move(mState))
	             .against(
	                 [](Ready&& ready) -> State {
		                 if (ready.connected()) {
			                 return Disconnecting(std::move(ready));
		                 } else {
			                 // If the context is not connected, hiredis would free the context immediately
			                 // anyway and *not* call the onDisconnect callback leaving us with a dangling
			                 // pointer in a Disconnecting state
			                 return Disconnected();
		                 }
	                 },
	                 [](Disconnecting&& disconnecting) -> State { return std::move(disconnecting); },
	                 [](auto&&) -> State { return Disconnected(); });
	if (auto* disconnecting = std::get_if<Disconnecting>(&mState)) {
		disconnecting->disconnect();
		// Might call onDisconnect synchronously if there are no pending callbacks.
		// We must do that *after* switching states, otherwise we'd end up in an illegal partially moved state.
	}
	return mState;
}
void Session::forceDisconnect() {
	mState = Disconnected();
}

void Session::onConnect(const redisAsyncContext*, int status) {
	mState = Match(std::move(mState))
	             .against(
	                 [&prefix = this->mLogPrefix, status](Ready&& ready) -> State {
		                 if (status == REDIS_OK) {
			                 LOGI_CTX(prefix, "onConnect") << "Connected";
			                 return std::move(ready);
		                 }

		                 LOGE_CTX(prefix, "onConnect") << "Could not connect to redis: " << ready.mCtx->errstr;
		                 // The context will be freed by hiredis right after this callback. Prevent double-freeing
		                 std::ignore = ready.mCtx.release();
		                 return Disconnected();
	                 },
	                 [&prefix = this->mLogPrefix, status](auto&& unexpectedState) -> State {
		                 LOGE_CTX(prefix, "onConnect")
		                     << "Called with status " << status << " while in state " << unexpectedState;
		                 return std::move(unexpectedState);
	                 });
	if (auto listener = mListener.lock()) {
		listener->onConnect(status);
	}
}

void Session::onDisconnect(const redisAsyncContext* ctx, int status) {
	const auto* ourCtx =
	    Match(mState).against([](const Disconnected&) -> AsyncContextPtr::pointer { return nullptr; },
	                          [](const auto& state) -> AsyncContextPtr::pointer { return state.mCtx.get(); });
	if (ourCtx != ctx) {
		LOGD << "Zombie context " << ctx << " is trying to call us from beyond the grave: ignore it (ours is " << ourCtx
		     << ")";
		// This happens when `forceDisconnect` is called from within a command callback. `redisAsyncFree` bails out and
		// schedules the actual destruction to the next loop iteration. By the time we're being called back we have
		// already updated our state so it would be harmful to do anything here.
		return;
	}

	if (status != REDIS_OK) {
		LOGW << "Forcefully disconnecting, reason: " << ctx->errstr;
	}
	LOGI << "Disconnected, was in state: " << StreamableVariant(mState);
	mState = Disconnected();
	if (auto listener = mListener.lock()) {
		listener->onDisconnect(status);
	}
}

Session::Ready::Ready(AsyncContextPtr&& ctx) : mCtx(std::move(ctx)) {
}
Session::Disconnecting::Disconnecting(Ready&& prev) : mCtx(std::move(prev.mCtx)) {
}

void Session::Disconnecting::disconnect() {
	redisAsyncDisconnect(mCtx.get());
}

void Session::Ready::command(const ArgsPacker& args, CommandCallback&& callback) const {
	static const std::regex sSubscribePattern{".*SUBSCRIBE",
	                                          std::regex::icase | std::regex::basic | std::regex::optimize};
	if (std::regex_match(args.command(), sSubscribePattern)) {
		throw std::invalid_argument{"Subscription commands cannot be sent with a regular (command) session. Please use "
		                            "a SubscriptionSession for those."};
	}

	auto* capturedData = new CommandCallback(std::move(callback));
	int status =
	    command(args, capturedData, [](redisAsyncContext* asyncCtx, void* reply, void* rawCommandData) noexcept {
		    std::unique_ptr<CommandCallback> callback{static_cast<CommandCallback*>(rawCommandData)};

		    auto& sessionContext = *static_cast<Session*>(asyncCtx->data);
		    if (callback && *callback) {
			    try {
				    (*callback)(sessionContext, reply::tryFrom(static_cast<const redisReply*>(reply)));
			    } catch (const std::exception& exc) {
				    LOGE_CTX(sessionContext.mLogPrefix, "command")
				        << "Unhandled exception in Redis callback: " << exc.what();
			    } catch (...) {
				    LOGE_CTX(sessionContext.mLogPrefix, "command") << "Unidentified thrown object in Redis callback";
			    }
		    }
	    });
	if (status != REDIS_OK) {
		// All other preconditions are checked, hiredis must have failed to allocate memory.
		// Not much we can do, let's at least avoid leaking more memory
		delete capturedData;
		throw std::bad_alloc{};
	}
}

auto& SubscriptionSession::getSubscriptionsFrom(const redisAsyncContext* rawContext) {
	auto* wrappedSession = static_cast<Session*>(rawContext->data);
	auto listener = wrappedSession->mListener.lock();
	// Retrieve the back-reference to ourself. We know it to be non-null by construction
	assert(bool(listener));
	auto* self = static_cast<SubscriptionSession*>(listener.operator->());
	return self->mSubscriptions;
}

SubscriptionSession::SubscriptionSession(const ConnectionParameters& connectionParams,
                                         SoftPtr<SessionListener>&& listener)
    : mListener(std::move(listener)),
      mWrapped(connectionParams, SoftPtr<SessionListener>::fromObjectLivingLongEnough(*this)),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "SubscriptionSession")) {
}

SubscriptionSession::Subscriptions SubscriptionSession::Ready::subscriptions() const {
	return {mWrapped, getSubscriptionsFrom(mWrapped.mCtx.get())};
}

SubscriptionSession::Subscriptions::Subscriptions(const Session::Ready& session, SubsMap& map)
    : mSession(session), mMap(map) {
}

SubscriptionSession::SubscriptionEntry SubscriptionSession::Subscriptions::operator[](const std::string_view& topic) {
	return {mSession, mMap, topic};
}

SubscriptionSession::SubsMap::size_type SubscriptionSession::Subscriptions::size() const {
	return mMap.size();
}

SubscriptionSession::SubscriptionEntry ::SubscriptionEntry(const Session::Ready& session,
                                                           SubsMap& map,
                                                           const std::string_view& topic)
    : mSession(session), mMap(map), mChannel(topic), mSlot(mMap.find(mChannel)) {
}

bool SubscriptionSession::SubscriptionEntry::isInMap() const {
	return mSlot != mMap.end();
}

bool SubscriptionSession::SubscriptionEntry::subscribed() const {
	return isInMap();
}

bool SubscriptionSession::SubscriptionEntry::isFresh() const {
	return mSlot->second.fresh;
}

void SubscriptionSession::SubscriptionEntry::subscribe(SubscriptionCallback&& callback) {
	{
		Subscription newSub{.callback = std::move(callback), .fresh = true, .unsubbed = false};
		if (isInMap()) {
			mSlot->second = std::move(newSub);
		} else {
			mSlot = mMap.emplace(mChannel, std::move(newSub)).first;
		}
	}

	// SAFETY: This pointer will remain valid for as long as the entry exists in the map.
	// Neither adding nor removing elements from the map will invalidate it.
	auto nodePtr = std::addressof(*mSlot);
	int status = mSession.command(
	    {"SUBSCRIBE", mChannel}, nodePtr, [](redisAsyncContext* asyncCtx, void* rawReply, void* rawHandle) noexcept {
		    auto reply = reply::tryFrom(static_cast<const redisReply*>(rawReply));
		    auto* const handle = static_cast<decltype(nodePtr)>(rawHandle);
		    auto& subscription = handle->second;
		    // Tag subscription as having been answered
		    subscription.fresh = false;
		    // We'd like to determine if we should free the subscription from the map after the callback finishes
		    // (i.e. when the Redis server no longer has knowledge of this subscription on its side, and won't send us
		    // replies to that topic.)
		    auto serverHasIt = true;
		    // So let's just fetch the info we need in the reply before forwarding it. (It will be the job of the
		    // callback to deal with any undocumented reply)
		    Match(reply).against([&serverHasIt](const reply::Disconnected&) { serverHasIt = false; },
		                         [&serverHasIt](const reply::Array& message) {
			                         if (message[0] == reply::String("unsubscribe")) serverHasIt = false;
		                         },
		                         [](const auto&) {});
		    if (const auto& callback = subscription.callback) {
			    try {
				    callback(handle->first, std::move(reply));
			    } catch (const std::exception& exc) {
				    LOGE_CTX("SubscriptionEntry", "subscribe")
				        << "Unhandled exception in Redis subscription callback: " << exc.what();
			    } catch (...) {
				    LOGE_CTX("SubscriptionEntry", "subscribe")
				        << "Unidentified thrown object in Redis subscription callback";
			    }
		    }
		    if (subscription.unsubbed && !serverHasIt) {
			    getSubscriptionsFrom(asyncCtx).erase(handle->first);
		    }
	    });
	if (status != REDIS_OK) {
		// All other preconditions are checked, hiredis must have failed to allocate memory.
		throw std::bad_alloc{};
	}
}

void SubscriptionSession::SubscriptionEntry::unsubscribe() {
	if (!isInMap()) return;

	mSlot->second.unsubbed = true;
	if (REDIS_OK != mSession.command({"UNSUBSCRIBE", mChannel}, nullptr, nullptr)) {
		throw std::bad_alloc{};
	}
}

void Session::Ready::auth(std::variant<auth::ACL, auth::Legacy> credentials, CommandCallback&& callback) const {
	command(Match(credentials)
	            .against([](redis::auth::Legacy legacy) -> ArgsPacker { return {"AUTH", legacy.password}; },
	                     [](redis::auth::ACL acl) -> ArgsPacker { return {"AUTH", acl.user, acl.password}; }),
	        std::move(callback));
}
void SubscriptionSession::Ready::auth(std::variant<auth::ACL, auth::Legacy> credentials,
                                      Session::CommandCallback&& callback) const {
	mWrapped.auth(credentials, std::move(callback));
}
void SubscriptionSession::Ready::ping(std::function<void(const Reply&)>&& callback) const {
	mWrapped.command({"PING"}, [callback = std::move(callback)](Session&, Reply reply) { callback(reply); });
}

int Session::Ready::command(const ArgsPacker& args, void* privdata, redisCallbackFn* fn) const {
	return redisAsyncCommandArgv(
	    mCtx.get(), fn, privdata, args.getArgCount(),
	    // This const char** signature supposedly suggests that while the elements are const, the array itself is not.
	    // But I don't see a reason the array would be modified by this function, so I assume this is just a mistake.
	    const_cast<const char**>(args.getCArgs()), args.getArgSizes());
}

const Session::State& Session::getState() const {
	return mState;
}

const std::string& Session::getLogPrefix() const {
	return mLogPrefix;
}

const SubscriptionSession::State& SubscriptionSession::getState() const {
	return reinterpret_cast<const State&>(mWrapped.getState());
}

void SubscriptionSession::onConnect(int status) {
	if (status == REDIS_OK) {
		auto* ready = tryGetState<Ready>();
		if (!ready) return; // unexpected

		auto newSubs = ready->subscriptions();
		auto reSubbedChannelsLog = std::ostringstream();
		reSubbedChannelsLog << "Channels automatically re-subscribed: (none)";
		reSubbedChannelsLog.seekp(-static_cast<int>(sizeof("(none)")));
		for (auto& [channel, subscription] : mSubscriptions) {
			// This `onConnect()` callback is called before responses are processed, so skip over any subscription
			// created early, we shall receive the answer shortly
			if (subscription.fresh) continue;

			if (subscription.unsubbed) {
				LOGW << "Memory leak detected: Redis subscription to '" << channel
				     << "' was unsubbed before the session was disconnected and never got cleaned up properly, "
				        "this should never happen (if you see this in your log, please open a ticket)";
				continue;
			};

			// Subscription created on a previous connection.
			// We have just reconnected successfully, let's re-subscribe it
			newSubs[channel].subscribe(std::move(subscription.callback));
			reSubbedChannelsLog << " '" << channel << "',";
		}
		LOGI << reSubbedChannelsLog.str();
	}

	if (auto listener = mListener.lock()) {
		listener->onConnect(status);
	}
}
void SubscriptionSession::onDisconnect(int status) {
	if (auto listener = mListener.lock()) {
		listener->onDisconnect(status);
	}
}

std::ostream& operator<<(std::ostream& stream, const Session::Disconnected&) {
	return stream << "Disconnected()";
}
std::ostream& operator<<(std::ostream& stream, const Session::Ready& ready) {
	auto* context = ready.mCtx.get();
	stream << std::boolalpha << "Ready(ctx: " << context;
	if (context) {
		stream << ", flags: 0b" << std::bitset<8>{static_cast<unsigned long>(context->c.flags)};
	}
	stream << ")";
	return stream;
}
std::ostream& operator<<(std::ostream& stream, const Session::Disconnecting& disconnecting) {
	return stream << "Disconnecting(ctx: " << disconnecting.mCtx.get() << ")";
}

bool Session::isConnected() const {
	return Match(mState).against([](const Ready& ready) { return ready.connected(); },
	                             [](const auto&) { return false; });
}

bool SubscriptionSession::isConnected() const {
	return mWrapped.isConnected();
}

} // namespace flexisip::redis::async