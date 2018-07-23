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

#ifndef registrardb_redis_hh
#define registrardb_redis_hh

#include "registrardb.hh"
#include "recordserializer.hh"
#include <sofia-sip/sip.h>
#include <sofia-sip/nta.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include "agent.hh"

struct RedisParameters {
	RedisParameters() : port(0), timeout(0) {
	}
	std::string domain;
	std::string auth;
	int port;
	int timeout;
	int mSlaveCheckTimeout;
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
 * RegistrarUserData helper class
 */
class RegistrarDbRedisAsync;
struct RegistrarUserData;

typedef void(forwardFn)(redisAsyncContext *, redisReply *, RegistrarUserData *);

struct RegistrarUserData {
	RegistrarDbRedisAsync *self;
	std::shared_ptr<ContactUpdateListener> listener;
	Record record;
	unsigned long token;
	su_timer_t *mRetryTimer;
	int mRetryCount;
	std::string mGruu;
	bool mUpdateExpire;
	bool mIsUnregister;

	RegistrarUserData(RegistrarDbRedisAsync *s, const url_t *url, std::shared_ptr<ContactUpdateListener> listener);
	~RegistrarUserData();
};

class RegistrarDbRedisAsync : public RegistrarDb {
  public:
	RegistrarDbRedisAsync(const std::string &preferredRoute, su_root_t *root, RecordSerializer *serializer,
						  RedisParameters params);

	bool connect();
	bool disconnect();

  protected:
	virtual void doBind(const url_t *ifrom, sip_contact_t *icontact, const char *iid, uint32_t iseq,
					  const sip_path_t *ipath, std::list<std::string> acceptHeaders, bool usedAsRoute, int expire, int alias, int version, 
					  const std::shared_ptr<ContactUpdateListener> &listener);
	virtual void doClear(const sip_t *sip, const std::shared_ptr<ContactUpdateListener> &listener);
	virtual void doFetch(const url_t *url, const std::shared_ptr<ContactUpdateListener> &listener);
	virtual void doFetchForGruu(const url_t *url, const std::string &gruu, const std::shared_ptr<ContactUpdateListener> &listener);
	virtual void doMigration();
	virtual void subscribe(const std::string &topic, const std::shared_ptr<ContactRegisteredListener> &listener);
	virtual void unsubscribe(const std::string &topic, const std::shared_ptr<ContactRegisteredListener> &listener);
	virtual void publish(const std::string &topic, const std::string &uid);

  private:
	RegistrarDbRedisAsync(Agent *agent, RedisParameters params);
	~RegistrarDbRedisAsync();
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
	redisAsyncContext *mContext, *mSubscribeContext;
	RecordSerializer *mSerializer;
	std::string mDomain;
	std::string mAuthPassword;
	int mPort;
	int mTimeout;
	su_root_t *mRoot;
	std::vector<RedisHost> mSlaves;
	size_t mCurSlave;
	su_timer_t *mReplicationTimer;
	int mSlaveCheckTimeout;
	/*std::list<RegistrarUserData*> mQueue;
	bool mAddToQueue;*/

	void serializeAndSendToRedis(RegistrarUserData *data, forwardFn *forward_fn);
	bool handleRedisStatus(const std::string &desc, int redisStatus, RegistrarUserData *data);
	void onErrorData(RegistrarUserData *data);
	void subscribeTopic(const std::string &topic);
	void subscribeAll();
	void subscribeToKeyExpiration();
	//void dequeueNextRedisCommand();

	/* callbacks */
	void handleAuthReply(const redisReply *reply);
	void handleBind(redisReply *reply, RegistrarUserData *data);
	void handleBindReplyAorSet(redisReply *reply, RegistrarUserData *data);
	void handleClear(redisReply *reply, RegistrarUserData *data);
	void handleFetch(redisReply *reply, RegistrarUserData *data);
	void handleReplicationInfoReply(const char *str);
	void handleMigration(redisReply *reply, RegistrarUserData *data);
	void handleRecordMigration(redisReply *reply, RegistrarUserData *data);
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
	static void shandleAuthReply(redisAsyncContext *ac, void *r, void *privdata);
	static void sHandleBind(redisAsyncContext *ac, redisReply *reply, RegistrarUserData *data);
	static void sHandleClear(redisAsyncContext *ac, redisReply *reply, RegistrarUserData *data);
	static void sHandleFetch(redisAsyncContext *ac, redisReply *reply, RegistrarUserData *data);
	static void sHandleInfoTimer(void *unused, su_timer_t *t, void *data);
	static void sHandleReplicationInfoReply(redisAsyncContext *ac, void *r, void *privdata);
	static void sHandleSet(redisAsyncContext *ac, void *r, void *privdata);
	static void sHandleMigration(redisAsyncContext *ac, redisReply *reply, RegistrarUserData *data);
	static void sHandleRecordMigration(redisAsyncContext *ac, redisReply *reply, RegistrarUserData *data);
};

#endif
