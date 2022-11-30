/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "compat/hiredis/hiredis.h"
#include "compat/hiredis/async.h"

#include <sofia-sip/nta.h>
#include <sofia-sip/sip.h>

#include "flexisip/agent.hh"
#include "flexisip/registrardb.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "recordserializer.hh"

namespace flexisip {

struct RedisParameters {
	std::string domain{};
	std::string auth{};
	int port = 0;
	int timeout = 0;
	std::chrono::seconds mSlaveCheckTimeout{0};
	bool useSlavesAsBackup = true;
};

/**
 * @brief The RedisHost struct, which is used to store redis slave description.
 */
struct RedisHost {
	RedisHost(int id, const std::string &address, unsigned short port, const std::string &state)
		: id(id), address(address), port(port), state(state) {
	}

	RedisHost() {
		// invalid host
		id = -1;
	}

	inline bool operator==(const RedisHost &r) {
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
	static RedisHost parseSlave(const std::string &slaveLine, int id);
	int id;
	std::string address;
	unsigned short port;
	std::string state;
};



/******
 * RedisRegisterContext helper class
 */
class RegistrarDbRedisAsync;
struct RedisRegisterContext;

typedef void(forwardFn)(redisAsyncContext *, redisReply *, RedisRegisterContext *);

struct RedisRegisterContext {
	RegistrarDbRedisAsync *self = nullptr;
	std::shared_ptr<ContactUpdateListener> listener;
	std::shared_ptr<Record> mRecord;
	unsigned long token = 0;
	su_timer_t *mRetryTimer = nullptr;
	int mRetryCount = 0;
	MsgSip mMsg;
	BindingParameters mBindingParameters;
	std::string mUniqueIdToFetch;
	bool mUpdateExpire = false;

	template <typename T>
	RedisRegisterContext(RegistrarDbRedisAsync *s, T &&url, const std::shared_ptr<ContactUpdateListener> &listener) :
		self(s), listener(listener), mRecord(std::make_shared<Record>(std::forward<T>(url))) {}
	RedisRegisterContext(RegistrarDbRedisAsync *s, const MsgSip &msg, const BindingParameters &params, const std::shared_ptr<ContactUpdateListener> &listener) :
		self(s), listener(listener), 
		mRecord(std::make_shared<Record>(SipUri(msg.getSip()->sip_from->a_url))), 
			mMsg(const_cast<MsgSip&>(msg).getMsg()), // Forcefully take a ref, instead of cloning
			mBindingParameters(params) {
			// Note that MsgSip copy constructor is not invoked in order to avoid a deep copy.
			// Instead, mMsg just takes a ref on the underlying sofia-sip msg_t.
		}
};

/* Utility struct to create argument vectors to pass to redis, for HSET and HDEL requests for example.*/
class RedisArgsPacker{
public:
	RedisArgsPacker(const std::string &command, const std::string &key){
		addArg(command);
		addArg(key);
	}
	void addPair(const std::string & fieldName, const std::string &value){
		addArg(fieldName);
		addArg(value);
	}
	void addFieldName(const std::string & fieldName){
		addArg(fieldName);
	}
	const char **getCArgs(){
		return &mCArgs[0];
	}
	const size_t *getArgSizes(){
		return &mArgsSize[0];
	}
	size_t getArgCount()const{
		return mCArgs.size();
	}
private:
	void addArg(const std::string &arg){
		mArgs.emplace_back(arg);
		mCArgs.emplace_back(mArgs.back().c_str()); // The C string pointer is held within mArgs
		mArgsSize.push_back(arg.size());
	}
	std::list<std::string> mArgs;
	std::vector<const char*> mCArgs;
	std::vector<size_t> mArgsSize; 
};

class RegistrarDbRedisAsync : public RegistrarDb {
public:
	RegistrarDbRedisAsync(Agent* agent, RedisParameters params);
	RegistrarDbRedisAsync(const std::string& preferredRoute, const std::shared_ptr<sofiasip::SuRoot>& root, RecordSerializer* serializer,
	                      RedisParameters params);
	~RegistrarDbRedisAsync() override;

	void fetchExpiringContacts(time_t startTimestamp,
	                           std::chrono::seconds timeRange,
	                           std::function<void(std::vector<ExtendedContact>&&)>&& callback) const override;

	bool connect();
	bool disconnect();

protected:
	void doBind(const MsgSip &msg, const BindingParameters &parameters, const std::shared_ptr<ContactUpdateListener> &listener) override;
	void doClear(const MsgSip &msg, const std::shared_ptr<ContactUpdateListener> &listener) override;
	void doFetch(const SipUri &url, const std::shared_ptr<ContactUpdateListener> &listener) override;
	void doFetchInstance(const SipUri &url, const std::string &uniqueId, const std::shared_ptr<ContactUpdateListener> &listener) override;
	void doMigration() override;
	bool subscribe(const std::string& topic, const std::shared_ptr<ContactRegisteredListener>& listener) override;
	void unsubscribe(const std::string& topic, const std::shared_ptr<ContactRegisteredListener>& listener) override;
	void publish(const std::string &topic, const std::string &uid) override;

private:
	static void sConnectCallback(const redisAsyncContext *c, int status);
	static void sDisconnectCallback(const redisAsyncContext *c, int status);
	static void sSubscribeConnectCallback(const redisAsyncContext *c, int status);
	static void sSubscribeDisconnectCallback(const redisAsyncContext *c, int status);
	static void sPublishCallback(redisAsyncContext *c, void *r, void *privdata);
	static void sKeyExpirationPublishCallback(redisAsyncContext *c, void *r, void *data);
	static void sBindRetry(void *unused, su_timer_t *t, void *ud);
	bool isConnected();
	void setWritable (bool value);

	friend class RegistrarDb;

	void serializeAndSendToRedis(RedisRegisterContext *data, forwardFn *forward_fn);
	bool handleRedisStatus(const std::string &desc, int redisStatus, RedisRegisterContext *data);
	void onErrorData(RedisRegisterContext *data);
	void subscribeTopic(const std::string &topic);
	void subscribeAll();
	void subscribeToKeyExpiration();
	void parseAndClean(redisReply *reply, RedisRegisterContext *data);

	/* callbacks */
	void handleAuthReply(const redisReply *reply);
	void handleBind(redisReply *reply, RedisRegisterContext *data);
	void handleBindReplyAorSet(redisReply *reply, RedisRegisterContext *data);
	void handleClear(redisReply *reply, RedisRegisterContext *data);
	void handleFetch(redisReply *reply, RedisRegisterContext *data);
	
	/**
	 * This callback is called when the Redis instance answered our "INFO replication" message.
	 * We parse the response to determine if we are connected to the master Redis instance or
	 * a slave, and we react accordingly.
	 * @param str Redis answer
	 */
	void handleReplicationInfoReply(const char *str);
	void handleMigration(redisReply *reply, RedisRegisterContext *data);
	void handleRecordMigration(redisReply *reply, RedisRegisterContext *data);
	void onConnect(const redisAsyncContext *c, int status);
	void onDisconnect(const redisAsyncContext *c, int status);
	void onSubscribeConnect(const redisAsyncContext *c, int status);
	void onSubscribeDisconnect(const redisAsyncContext *c, int status);

	/* replication */
	void getReplicationInfo();
	void updateSlavesList(const std::map<std::string, std::string> redisReply);
	void tryReconnect();

	/* static handlers */
	//static void sHandleAorGetReply(struct redisAsyncContext *, void *r, void *privdata);
	static void sHandleAuthReply(redisAsyncContext *ac, void *r, void *privdata);
	static void sHandleBindStart(redisAsyncContext *ac, redisReply *reply, RedisRegisterContext *data);
	static void sHandleBindFinish(redisAsyncContext *ac, redisReply *reply, RedisRegisterContext *data);
	static void sHandleClear(redisAsyncContext *ac, redisReply *reply, RedisRegisterContext *data);
	static void sHandleFetch(redisAsyncContext *ac, redisReply *reply, RedisRegisterContext *data);
	static void sHandleReplicationInfoReply(redisAsyncContext *ac, void *r, void *privdata);
	static void sHandleSet(redisAsyncContext *ac, void *r, void *privdata);
	static void sHandleMigration(redisAsyncContext *ac, redisReply *reply, RedisRegisterContext *data);
	static void sHandleRecordMigration(redisAsyncContext *ac, redisReply *reply, RedisRegisterContext *data);

	/**
	 * This callback is called periodically to check if the current REDIS connection is valid
	 */
	void onHandleInfoTimer();

	/**
	 * Callback use to add space between RegistrarDbRedisAsync::tryReconnect calls
	 */
	void onTryReconnectTimer();

	redisAsyncContext* mContext{nullptr};
	redisAsyncContext* mSubscribeContext{nullptr};
	RecordSerializer* mSerializer;
	RedisParameters mParams{};
	RedisParameters mLastActiveParams{};
	std::shared_ptr<sofiasip::SuRoot> mRoot{};
	std::vector<RedisHost> mSlaves{};
	decltype(mSlaves)::const_iterator mCurSlave = mSlaves.cend();
	std::unique_ptr<sofiasip::Timer> mReplicationTimer{nullptr};
	std::unique_ptr<sofiasip::Timer> mReconnectTimer{nullptr};
	std::chrono::system_clock::time_point mLastReconnectRotation;
};

} // namespace flexisip
