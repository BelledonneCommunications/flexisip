/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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

#include "libhiredis-wrapper/redis-args-packer.hh"
#include "libhiredis-wrapper/redis-auth.hh"
#include "libhiredis-wrapper/redis-reply.hh"
#include "registrardb-redis-sofia-event.h"
#include "sofia-sip/su_wait.h"
#include "utils/stl-backports.hh"
#include "utils/variant-utils.hh"

using namespace std::string_view_literals;

namespace flexisip::redis::async {

Session::Session(SoftPtr<SessionListener>&& listener) : mListener(std::move(listener)) {
	std::stringstream prefix{};
	prefix << "redis::async::Session[" << this << "] - ";
	mLogPrefix = prefix.str();
}

const Session::State& Session::connect(su_root_t* sofiaRoot, const std::string_view& address, int port) {
	[&]() {
		if (auto* ready = std::get_if<Ready>(&mState)) {
			SLOGD << mLogPrefix << ".connect() called on " << *ready << ". noop.";
			return;
		}

		ContextPtr ctx{redisAsyncConnect(address.data(), port)};
		if (ctx == nullptr) {
			throw std::bad_alloc{};
		}

		if (ctx->err) {
			SLOGE << mLogPrefix << "Connection error: " << ctx->err;
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
			SLOGE << mLogPrefix << "Failed to hook into Sofia loop: " << ::strerror(errno);
			return;
		}

		mState = Ready(std::move(ctx));
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
			                 SLOGD << prefix << "Connected";
			                 return std::move(ready);
		                 }

		                 SLOGE << prefix << "Couldn't connect to redis: " << ready.mCtx->errstr;
		                 // The context will be freed by hiredis right after this callback. Prevent double-freeing
		                 std::ignore = ready.mCtx.release();
		                 return Disconnected();
	                 },
	                 [&prefix = this->mLogPrefix, status](auto&& unexpectedState) -> State {
		                 SLOGE << prefix << "onConnect called with status " << status << " while in state "
		                       << unexpectedState;
		                 return std::move(unexpectedState);
	                 });
	if (auto listener = mListener.lock()) {
		listener->onConnect(status);
	}
}

void Session::onDisconnect(const redisAsyncContext* ctx, int status) {
	if (status != REDIS_OK) {
		SLOGW << mLogPrefix << "Forcefully disconnecting. Reason: " << ctx->errstr;
	}
	SLOGD << mLogPrefix << "Disconnected. Was in state: " << StreamableVariant(mState);
	mState = Disconnected();
	if (auto listener = mListener.lock()) {
		listener->onDisconnect(status);
	}
}

Session::Ready::Ready(ContextPtr&& ctx) : mCtx(std::move(ctx)) {
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
				    SLOGE << "Unhandled exception in Redis callback: " << exc.what();
			    } catch (...) {
				    SLOGE << "Unidentified Thrown Object in Redis callback";
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

SubscriptionSession::SubscriptionSession(SoftPtr<SessionListener>&& listener)
    : mListener(std::move(listener)), mWrapped(SoftPtr<SessionListener>::fromObjectLivingLongEnough(*this)) {
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

void SubscriptionSession::SubscriptionEntry::subscribe(SubscriptionCallback&& callback) {
	{
		Subscription newSub{.callback = std::move(callback), .state = Subscription::State::Pending};
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
		    const auto handle = static_cast<decltype(nodePtr)>(rawHandle);
		    auto& subscription = handle->second;
		    bool deleteIt = Match(reply).against(
		        [&subscription](const reply::Array& message) {
			        try {
				        const auto type = std::get<reply::String>(message[0]);
				        if (type == "unsubscribe") return true;
				        if (type == "subscribe") subscription.state = Subscription::State::Active;
				        return false;
			        } catch (const std::bad_variant_access&) {
				        return false;
			        }
		        },
		        [](const auto&) { return false; });
		    if (const auto& callback = subscription.callback) {
			    try {
				    callback(std::move(reply));
			    } catch (const std::exception& exc) {
				    SLOGE << "Unhandled exception in Redis subscription callback: " << exc.what();
			    } catch (...) {
				    SLOGE << "Unidentified Thrown Object in Redis subscription callback";
			    }
		    }
		    if (deleteIt && subscription.state == Subscription::State::Unsubbed) {
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

	mSlot->second.state = Subscription::State::Unsubbed;
	if (REDIS_OK != mSession.command({"UNSUBSCRIBE", mChannel}, nullptr, nullptr)) {
		throw std::bad_alloc{};
	}
}

void Session::Ready::auth(std::variant<auth::ACL, auth::Legacy> credentials, CommandCallback&& callback) const {
	command(Match(credentials)
	            .against(
	                [](redis::auth::Legacy legacy) -> ArgsPacker {
		                return {"AUTH", legacy.password};
	                },
	                [](redis::auth::ACL acl) -> ArgsPacker {
		                return {"AUTH", acl.user, acl.password};
	                }),
	        std::move(callback));
}
void SubscriptionSession::Ready::auth(std::variant<auth::ACL, auth::Legacy> credentials,
                                      Session::CommandCallback&& callback) const {
	mWrapped.auth(credentials, std::move(callback));
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

const SubscriptionSession::State& SubscriptionSession::getState() const {
	return reinterpret_cast<const State&>(mWrapped.getState());
}

void SubscriptionSession::onConnect(int status) {
	if (status == REDIS_OK) {
		auto* ready = tryGetState<Ready>();
		if (!ready) return; // unexpected

		auto newSubs = ready->subscriptions();
		for (auto&& entry : mSubscriptions) {
			auto&& subscription = entry.second;
			if (subscription.state != Subscription::State::Active) continue;

			newSubs[entry.first].subscribe(std::move(subscription.callback));
		}
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
	return stream << std::boolalpha << "Ready(ctx: " << context << ", flags: 0b"
	              << std::bitset<8>{static_cast<unsigned long>(context->c.flags)} << ")";
}
std::ostream& operator<<(std::ostream& stream, const Session::Disconnecting& disconnecting) {
	return stream << "Disconnecting(ctx: " << disconnecting.mCtx.get() << ")";
}

void Session::ContextDeleter::operator()(redisAsyncContext* ctx) noexcept {
	if (ctx->c.flags & (REDIS_FREEING | REDIS_DISCONNECTING)) {
		// The context is already halfway through freeing/disconnecting and we're probably in a disconnect callback
		return;
	}

	redisAsyncFree(ctx);
}

bool Session::isConnected() const {
	return Match(mState).against([](const Ready& ready) { return ready.connected(); },
	                             [](const auto&) { return false; });
}

bool SubscriptionSession::isConnected() const {
	return mWrapped.isConnected();
}

} // namespace flexisip::redis::async
