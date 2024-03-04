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
#include "libhiredis-wrapper/redis-auth.hh"
#include "libhiredis-wrapper/redis-reply.hh"
#include "recordserializer.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/change-set.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"

namespace flexisip {

struct RedisParameters {
	std::string domain{};
	std::variant<redis::auth::None, redis::auth::Legacy, redis::auth::ACL> auth{};
	int port = 0;
	int timeout = 0;
	std::chrono::seconds mSlaveCheckTimeout{0};
	bool useSlavesAsBackup = true;
};

/**
 * @brief The RedisHost struct, which is used to store redis slave description.
 */
struct RedisHost {
	RedisHost(int id, const std::string& address, unsigned short port, const std::string& state)
	    : id(id), address(address), port(port), state(state) {
	}

	RedisHost() {
		// invalid host
		id = -1;
	}

	inline bool operator==(const RedisHost& r) {
		return id == r.id && address == r.address && port == r.port && state == r.state;
	}

	/**
	 * @brief parseSlave this class method will parse a line from Redis where a slave information is expected.
	 *
	 * If the parsing goes well, the returned RedisHost will have the id field set to the one passed as argument,
	 * otherwise -1.
	 * @param slaveLine the Redis answer line where a slave is defined. Format is "host,port,state"
	 * @param id an ID to give to this slave, usually its number.
	 * @return A RedisHost with a valid ID or -1 if the parsing failed.
	 */
	static RedisHost parseSlave(const std::string& slaveLine, int id);
	int id;
	std::string address;
	unsigned short port;
	std::string state;
};

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
class RegistrarDbRedisAsync : public RegistrarDbBackend, redis::async::SessionListener {
public:
	RegistrarDbRedisAsync(const sofiasip::SuRoot& root,
	                      const Record::Config& recordConfig,
	                      LocalRegExpire& localRegExpire,
	                      RedisParameters params,
	                      std::function<void(const Record::Key&, const std::string&)> notifyContact,
	                      std::function<void(bool)> notifyState);
	RegistrarDbRedisAsync(const sofiasip::SuRoot& root,
	                      const Record::Config& recordConfig,
	                      LocalRegExpire& localRegExpire,
	                      RecordSerializer* serializer,
	                      RedisParameters params,
	                      std::function<void(const Record::Key&, const std::string&)> notifyContact,
	                      std::function<void(bool)> notifyState);

	void fetchExpiringContacts(time_t startTimestamp,
	                           float threshold,
	                           std::function<void(std::vector<ExtendedContact>&&)>&& callback) const override;

	std::optional<std::tuple<const redis::async::Session::Ready&, const redis::async::SubscriptionSession::Ready&>>
	connect();
	void asyncDisconnect();
	void forceDisconnect();
	bool isConnected() const;
	bool isWritable() const override {
		return mWritable;
	}

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
	const redis::async::Session::Ready* tryGetCommandSession();

	void serializeAndSendToRedis(RedisRegisterContext&, redis::async::Session::CommandCallback&&);
	void subscribeTopic(const std::string& topic);
	void subscribeToKeyExpiration();
	static std::vector<std::unique_ptr<ExtendedContact>> parseContacts(const redis::reply::ArrayOfPairs&,
	                                                                   const std::string& messageExpiresName);

	/* callbacks */
	void handleAuthReply(redis::async::Reply reply);
	void handleBind(redis::async::Reply, std::unique_ptr<RedisRegisterContext>&&);
	void handleClear(redis::async::Reply, const RedisRegisterContext&);
	void handleFetch(redis::async::Reply, const RedisRegisterContext&);
	void handlePublish(redis::async::Reply);

	/**
	 * This callback is called when the Redis instance answered our "INFO replication" message.
	 * We parse the response to determine if we are connected to the master Redis instance or
	 * a slave, and we react accordingly.
	 * @param str Redis answer
	 */
	void handleReplicationInfoReply(const redis::reply::String& str);

	/* redis::async::SessionListener */
	void onConnect(int status) override;
	void onDisconnect(int status) override;

	/* replication */
	void getReplicationInfo(const redis::async::Session::Ready&);
	void updateSlavesList(const std::map<std::string, std::string>& redisReply);
	void tryReconnect();

	/**
	 * This callback is called periodically to check if the current REDIS connection is valid
	 */
	void onHandleInfoTimer();

	/**
	 * Callback use to add space between RegistrarDbRedisAsync::tryReconnect calls
	 */
	void onTryReconnectTimer();

	// First member so it is destructed last and still valid when destructing the redis sessions
	const sofiasip::SuRoot& mRoot;
	const Record::Config& mRecordConfig;
	LocalRegExpire& mLocalRegExpire;
	redis::async::Session mCommandSession{};
	redis::async::SubscriptionSession mSubscriptionSession{};
	RecordSerializer* mSerializer;
	RedisParameters mParams{};
	RedisParameters mLastActiveParams{};
	std::vector<RedisHost> mSlaves{};
	decltype(mSlaves)::const_iterator mCurSlave = mSlaves.cend();
	std::unique_ptr<sofiasip::Timer> mReplicationTimer{nullptr};
	std::unique_ptr<sofiasip::Timer> mReconnectTimer{nullptr};
	std::chrono::system_clock::time_point mLastReconnectRotation;
	std::function<void(const Record::Key&, const std::string&)> mNotifyContactListener;
	std::function<void(bool)> mNotifyStateListener;
	bool mWritable{};
};

} // namespace flexisip
