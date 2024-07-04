/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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
#include <string>
#include <variant>
#include <vector>

#include "compat/hiredis/async.h"
#include "compat/hiredis/hiredis.h"

#include <sofia-sip/nta.h>
#include <sofia-sip/sip.h>

#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "libhiredis-wrapper/redis-async-session.hh"
#include "libhiredis-wrapper/redis-reply.hh"
#include "libhiredis-wrapper/replication/redis-client.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/change-set.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"

namespace flexisip {

class RegistrarDbRedisAsync;
struct RedisRegisterContext;

typedef void(forwardFn)(redisAsyncContext*, redisReply*, RedisRegisterContext*);

/******
 * RedisRegisterContext helper class
 */
struct RedisRegisterContext {
	RegistrarDbRedisAsync* self = nullptr;
	std::shared_ptr<ContactUpdateListener> listener;
	std::shared_ptr<Record> mRecord;
	ChangeSet mChangeSet{};
	unsigned long token = 0;
	std::unique_ptr<sofiasip::Timer> mRetryTimer;
	int mRetryCount = 0;
	bool mUpdateExpire = false;
	MsgSip mMsg;
	BindingParameters mBindingParameters;
	std::string mUniqueIdToFetch;

	template <typename T>
	RedisRegisterContext(RegistrarDbRedisAsync* s,
	                     T&& url,
	                     const std::shared_ptr<ContactUpdateListener>& listener,
	                     const Record::Config& recordConfig)
	    : self(s), listener(listener), mRecord(std::make_shared<Record>(std::forward<T>(url), recordConfig)) {
	}
	RedisRegisterContext(RegistrarDbRedisAsync* s,
	                     const MsgSip& msg,
	                     const BindingParameters& params,
	                     const std::shared_ptr<ContactUpdateListener>& listener,
	                     const Record::Config& recordConfig)
	    : self(s), listener(listener),
	      mRecord(std::make_shared<Record>(SipUri(msg.getSip()->sip_from->a_url), recordConfig)),
	      mMsg(const_cast<MsgSip&>(msg).getMsg()), // Forcefully take a ref, instead of cloning
	      mBindingParameters(params) {
		// Note that MsgSip copy constructor is not invoked in order to avoid a deep copy.
		// Instead, mMsg just takes a ref on the underlying sofia-sip msg_t.
	}
};

/**
 * An implementation of the RegistrarDb interface backend by a Redis server
 */
class RegistrarDbRedisAsync : public RegistrarDbBackend, public redis::async::SessionListener {
public:
	/**
	 * @param notifyContact The second parameter is the unique ID of the contact within the AoR. A `std::nullopt` value
	 * indicates that the Redis subscription received an unprocessable message. This should never happen under any
	 * circumstances, see REDISPUBSUBFORMAT.
	 */
	RegistrarDbRedisAsync(const sofiasip::SuRoot& root,
	                      const Record::Config& recordConfig,
	                      LocalRegExpire& localRegExpire,
	                      const redis::async::RedisParameters& params,
	                      std::function<void(const Record::Key&, std::optional<std::string_view>)> notifyContact,
	                      std::function<void(bool)> notifyState);

	void fetchExpiringContacts(time_t startTimestamp,
	                           float threshold,
	                           std::function<void(std::vector<ExtendedContact>&&)>&& callback) const override;

	std::optional<std::tuple<const redis::async::Session::Ready&, const redis::async::SubscriptionSession::Ready&>>
	connect();
	bool isConnected() const;
	bool isWritable() const override {
		return mWritable;
	}
	const redis::async::RedisClient& getRedisClient() const {
		return mRedisClient;
	}

	static void forceDisconnectForTest(RegistrarDbRedisAsync& thiz);

	/* The timeout to retry a bind request after encountering a failure. It gives us a chance to reconnect to a new
	 * master.*/
	static std::chrono::milliseconds bindRetryTimeout;

	void doBind(const MsgSip& msg,
	            const BindingParameters& parameters,
	            const std::shared_ptr<ContactUpdateListener>& listener) override;
	void doClear(const MsgSip& msg, const std::shared_ptr<ContactUpdateListener>& listener) override;
	void doFetch(const SipUri& url, const std::shared_ptr<ContactUpdateListener>& listener) override;
	void doFetchInstance(const SipUri& url,
	                     const std::string& uniqueId,
	                     const std::shared_ptr<ContactUpdateListener>& listener) override;
	void subscribe(const Record::Key& topic) override;
	void unsubscribe(const Record::Key& topic) override;
	void publish(const Record::Key& topic, const std::string& uid) override;

private:
	static void sBindRetry(void* ud);
	void setWritable(bool value);

	void serializeAndSendToRedis(RedisRegisterContext&, redis::async::Session::CommandCallback&&);
	void subscribe(std::string_view topic);
	void subscribeToKeyExpiration();
	static std::vector<std::unique_ptr<ExtendedContact>> parseContacts(const redis::reply::ArrayOfPairs&,
	                                                                   const std::string& messageExpiresName);

	/* callbacks */
	void handleBind(redis::async::Reply, std::unique_ptr<RedisRegisterContext>&&);
	void handleClear(redis::async::Reply, const RedisRegisterContext&);
	void handleFetch(redis::async::Reply, const RedisRegisterContext&);
	void handlePublish(std::string_view, redis::async::Reply);

	/* redis::async::SessionListener */
	void onConnect(int status) override;
	void onDisconnect(int status) override;

	mutable redis::async::RedisClient mRedisClient;
	const sofiasip::SuRoot& mRoot;
	const Record::Config& mRecordConfig;
	LocalRegExpire& mLocalRegExpire;
	std::function<void(const Record::Key&, std::optional<std::string_view>)> mNotifyContactListener;
	std::function<void(bool)> mNotifyStateListener;
	bool mWritable{};
};

} // namespace flexisip
