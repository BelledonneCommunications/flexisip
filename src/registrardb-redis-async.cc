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

#include "recordserializer.hh"
#include "registrardb-redis.hh"
#include "common.hh"

#include <ctime>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <iterator>

#include "configmanager.hh"

#include <hiredis/hiredis.h>

#include "registrardb-redis-sofia-event.h"
#include <sofia-sip/sip_protos.h>

using namespace std;

/******
 * RegistrarUserData helper class
 */
typedef void(forwardFn)(redisAsyncContext *, redisReply *, RegistrarDbRedisAsync::RegistrarUserData *);

struct RegistrarDbRedisAsync::RegistrarUserData {
	RegistrarDbRedisAsync *self;
	char key[AOR_KEY_SIZE];
	forwardFn *fn;
	unsigned long token;
	const sip_contact_t *sipContact;
	std::string calldId;
	uint32_t csSeq;
	shared_ptr<RegistrarDbListener> listener;
	Record record;
	int globalExpire;
	const sip_path_t *path;
	bool alias;
	int mVersion;
	std::list<std::string> accept;
	bool mUsedAsRoute;
	su_home_t mHome;

	RegistrarUserData(RegistrarDbRedisAsync *s, const url_t *url, const sip_contact_t *sip_contact,
					  const std::string &calld_id, uint32_t cs_seq, const sip_path_t *p, bool alias, int version,
					  shared_ptr<RegistrarDbListener> listener, forwardFn *forward_fn)
		: token(0), calldId(calld_id), csSeq(cs_seq), listener(listener), record(""), globalExpire(0), alias(alias), mVersion(version), mUsedAsRoute(false) {
		su_home_init(&mHome);
		self = s;
		fn = forward_fn;
		sipContact = sip_contact_dup(&mHome, sip_contact);
		path = sip_path_dup(&mHome, p);
		self->defineKeyFromUrl(key, AOR_KEY_SIZE - 1, url);
		record.setKey(key);
	}
	RegistrarUserData(RegistrarDbRedisAsync *s, const url_t *url, const sip_contact_t *sip_contact,
					  const std::string &calld_id, uint32_t cs_seq, shared_ptr<RegistrarDbListener> listener, forwardFn *forward_fn)
		: token(0), calldId(calld_id), csSeq(cs_seq), listener(listener), record(""), globalExpire(0), mVersion(0), mUsedAsRoute(false) {
		su_home_init(&mHome);
		self = s;
		fn = forward_fn;
		sipContact = sip_contact_dup(&mHome, sip_contact);
		path = NULL;
		self->defineKeyFromUrl(key, AOR_KEY_SIZE - 1, url);
		record.setKey(key);
	}
	RegistrarUserData(RegistrarDbRedisAsync *s, const url_t *url, shared_ptr<RegistrarDbListener> listener, forwardFn *forward_fn)
		: token(0), calldId(NULL), csSeq(-1), listener(listener), record(""), globalExpire(0), mVersion(0), mUsedAsRoute(false) {
		su_home_init(&mHome);
		self = s;
		fn = forward_fn;
		sipContact = NULL;
		path = NULL;
		self->defineKeyFromUrl(key, AOR_KEY_SIZE - 1, url);
		record.setKey(key);
	}
	~RegistrarUserData() {
		su_home_deinit(&mHome);
	}
};

/******
 * RegistrarDbRedisAsync class
 */

RegistrarDbRedisAsync::RegistrarDbRedisAsync(Agent *ag, RedisParameters params)
	: RegistrarDb(ag->getPreferredRoute()), mAgent(ag), mContext(NULL), mSubscribeContext(NULL),
	  mDomain(params.domain), mAuthPassword(params.auth), mPort(params.port), mTimeout(params.timeout), mRoot(ag->getRoot()),
	  mReplicationTimer(NULL), mSlaveCheckTimeout(params.mSlaveCheckTimeout) {
	mSerializer = RecordSerializer::get();
	mCurSlave = 0;
}

RegistrarDbRedisAsync::RegistrarDbRedisAsync(const string &preferredRoute, su_root_t *root, RecordSerializer *serializer, RedisParameters params)
	: RegistrarDb(preferredRoute), mAgent(NULL), mContext(NULL), mSubscribeContext(NULL),
	  mDomain(params.domain), mAuthPassword(params.auth), mPort(params.port), mTimeout(params.timeout), mRoot(root),
	  mReplicationTimer(NULL), mSlaveCheckTimeout(params.mSlaveCheckTimeout) {
	mSerializer = serializer;
	mCurSlave = 0;
}

RegistrarDbRedisAsync::~RegistrarDbRedisAsync() {
	if (mContext) {
		redisAsyncDisconnect(mContext);
	}
	if (mSubscribeContext) {
		redisAsyncDisconnect(mSubscribeContext);
	}
	if (mAgent && mReplicationTimer) {
		mAgent->stopTimer(mReplicationTimer);
		mReplicationTimer = NULL;
	}
}

void RegistrarDbRedisAsync::onDisconnect(const redisAsyncContext *c, int status) {
	if (mContext != NULL && mContext != c) {
		LOGE("Redis context %p disconnected, but current context is %p", c, mContext);
		return;
	}

	mContext = NULL;
	LOGD("Disconnected %p...", c);
	if (status != REDIS_OK) {
		LOGE("Redis disconnection message: %s", c->errstr);
		tryReconnect();
		return;
	}
}

void RegistrarDbRedisAsync::onConnect(const redisAsyncContext *c, int status) {
	if (status != REDIS_OK) {
		LOGE("Couldn't connect to redis: %s", c->errstr);
		mContext = NULL;
		tryReconnect();
		return;
	}
	LOGD("Connected... %p", c);
}

void RegistrarDbRedisAsync::onSubscribeDisconnect(const redisAsyncContext *c, int status) {
	if (mSubscribeContext != NULL && mSubscribeContext != c) {
		LOGE("Redis context %p disconnected, but current context is %p", c, mSubscribeContext);
		return;
	}

	mSubscribeContext = NULL;
	LOGD("Disconnected %p...", c);
	if (status != REDIS_OK) {
		LOGE("Redis disconnection message: %s", c->errstr);
		tryReconnect();
		return;
	}
}

void RegistrarDbRedisAsync::onSubscribeConnect(const redisAsyncContext *c, int status) {
	if (status != REDIS_OK) {
		LOGE("Couldn't connect to redis: %s", c->errstr);
		mSubscribeContext = NULL;
		tryReconnect();
		return;
	}
	LOGD("Connected... %p", c);
}

bool RegistrarDbRedisAsync::isConnected() {
	return mContext != NULL;
}

/* This method checks that a redis command was successful, and cleans up if not. You use it with the macro defined
 * below. */

bool RegistrarDbRedisAsync::handleRedisStatus(const std::string &desc, int redisStatus, RegistrarUserData *data) {
	if (redisStatus != REDIS_OK) {
		LOGE("Redis error for %s: %d", desc.c_str(), redisStatus);
		if (data != NULL) {
			data->listener->onError();
			delete data;
		}
		return FALSE;
	}
	return TRUE;
}

#define check_redis_command(cmd, data)                                                                                 \
	do {                                                                                                               \
		if (handleRedisStatus(#cmd, (cmd), data) == FALSE) {                                                           \
			return;                                                                                                    \
		}                                                                                                              \
	} while (0)

static bool is_end_line_character(char c) {
	return c == '\r' || c == '\n';
}

/**
 * @brief parseKeyValue this functions parses a string contraining a list of key/value
 * separated by a delimiter, and for each key-value, another delimiter.
 * It converts the string to a map<string,string>.
 *
 * For instance:
 * <code>parseKeyValue("toto:tata\nfoo:bar", '\n', ':', '#')</code>
 * will give you:
 * <code>{ make_pair("toto","tata"), make_pair("foo", "bar") }</code>
 *
 * @param toParse the string to parse
 * @param delimiter the delimiter between key and value (default is ':')
 * @param comment a character which is a comment. Lines starting with this character
 * will be ignored.
 * @return a map<string,string> which contains the keys and values extracted (can be empty)
 */
static map<string, string> parseKeyValue(const std::string &toParse, const char line_delim = '\n',
										 const char delimiter = ':', const char comment = '#') {
	map<string, string> kvMap;
	istringstream values(toParse);

	for (string line; std::getline(values, line, line_delim);) {
		if (line.find(comment) == 0)
			continue; // section title

		// clear all non-UNIX end of line chars
		line.erase(remove_if(line.begin(), line.end(), is_end_line_character), line.end());

		size_t delim_pos = line.find(delimiter);
		if (delim_pos == line.npos || delim_pos == line.length()) {
			LOGW("Invalid line '%s' in key-value", line.c_str());
			continue;
		}

		const string key = line.substr(0, delim_pos);
		string value = line.substr(delim_pos + 1);

		kvMap[key] = value;
	}

	return kvMap;
}

RedisHost RedisHost::parseSlave(const string &slave, int id) {
	istringstream input(slave);
	vector<string> data;
	// a slave line has this format for redis < 2.8: "<host>,<port>,<state>"
	// for redis > 2.8 it is this format: "ip=<ip>,port=<port>,state=<state>,...(key)=(value)"

	// split the string with ',' into an array
	for (string token; getline(input, token, ',');)
		data.push_back(token);

	if (data.size() > 0 && (data.at(0).find('=') != string::npos)) {
		// we have found an "=" in one of the values: the format is post-Redis 2.8.
		// We have to parse is accordingly.
		auto m = parseKeyValue(slave, ',', '=');

		if (m.find("ip") != m.end() && m.find("port") != m.end() && m.find("state") != m.end()) {
			return RedisHost(id, m.at("ip"), atoi(m.at("port").c_str()), m.at("state"));
		} else {
			SLOGW << "Missing fields in the slaveline " << slave;
		}
	} else if (data.size() >= 3) {
		// Old-style slave format, use the data from the array directly
		return RedisHost(id, data[0],							// host
						 (unsigned short)atoi(data[1].c_str()), // port
						 data[2]);								// state
	} else {
		SLOGW << "Invalid host line: " << slave;
	}
	return RedisHost(); // invalid host
}

void RegistrarDbRedisAsync::updateSlavesList(const map<string, string> redisReply) {
	int slaveCount = atoi(redisReply.at("connected_slaves").c_str());

	vector<RedisHost> newSlaves;

	for (int i = 0; i < slaveCount; i++) {
		std::stringstream sstm;
		sstm << "slave" << i;
		string slaveName = sstm.str();

		if (redisReply.find(slaveName) != redisReply.end()) {

			RedisHost host = RedisHost::parseSlave(redisReply.at(slaveName), i);
			if (host.id != -1) {
				// only tell if a new host was found
				if (std::find(mSlaves.begin(), mSlaves.end(), host) == mSlaves.end()) {
					LOGD("Replication: Adding host %d %s:%d state:%s", host.id, host.address.c_str(), host.port,
						 host.state.c_str());
				}
				newSlaves.push_back(host);
			}
		}
	}

	// replace the slaves array
	mSlaves.clear();
	mSlaves = newSlaves;
}

void RegistrarDbRedisAsync::tryReconnect() {
	size_t slaveCount = mSlaves.size();
	if (slaveCount > 0 && !isConnected()) {
		// we are disconnected, but we can try one of the previously determined slaves
		mCurSlave++;
		mCurSlave = mCurSlave % slaveCount;
		RedisHost host = mSlaves[mCurSlave];

		LOGW("Connection lost to %s:%d, trying a known slave %d at %s:%d", mDomain.c_str(), mPort, host.id,
			 host.address.c_str(), host.port);

		mDomain = host.address;
		mPort = host.port;

		connect();
	} else {
		LOGW("No slave to try, giving up.");
	}
}

/* This callback is called when the Redis instance answered our "INFO replication" message.
 * We parse the response to determine if we are connected to the master Redis instance or
 * a slave, and we react accordingly. */
void RegistrarDbRedisAsync::handleReplicationInfoReply(const char *reply) {

	auto replyMap = parseKeyValue(reply);
	if (replyMap.find("role") != replyMap.end()) {
		string role = replyMap["role"];
		if (role == "master") {
			// we are speaking to the master, nothing to do but update the list of slaves
			updateSlavesList(replyMap);

		} else if (role == "slave") {

			// woops, we are connected to a slave. We should go to the master
			string masterAddress = replyMap["master_host"];
			int masterPort = atoi(replyMap["master_port"].c_str());
			string masterStatus = replyMap["master_link_status"];

			LOGW("Our redis instance is a slave of %s:%d", masterAddress.c_str(), masterPort);
			if (masterStatus == "up") {
				SLOGW << "Master is up, will attempt to connect to the master at " << masterAddress << ":"
					  << masterPort;

				mDomain = masterAddress;
				mPort = masterPort;

				// disconnect and reconnect immediately, dropping the previous context
				disconnect();
				connect();
			} else {
				SLOGW << "Master is " << masterStatus
					  << " but not up, wait for next periodic check to decide to connect.";
			}
		} else {
			SLOGW << "Unknown role '" << role << "'";
		}
		if (mAgent && mReplicationTimer == NULL) {
			SLOGD << "Creating replication timer with delay of " << mSlaveCheckTimeout << "s";
			mReplicationTimer = mAgent->createTimer(mSlaveCheckTimeout * 1000, sHandleInfoTimer, this);
		}
	} else {
		SLOGW << "Invalid INFO reply: no role specified";
	}
}

void RegistrarDbRedisAsync::handleAuthReply(const redisReply *reply) {
	if (!reply || reply->type == REDIS_REPLY_ERROR) {
		LOGE("Couldn't authenticate with redis server");
		disconnect();
	} else {
		getReplicationInfo();
	}
}

void RegistrarDbRedisAsync::getReplicationInfo() {
	redisAsyncCommand(mContext, sHandleReplicationInfoReply, this, "INFO replication");
	// Workaround for issue https://github.com/redis/hiredis/issues/396
	redisAsyncCommand(mSubscribeContext, sPublishCallback, NULL, "SUBSCRIBE %s", "FLEXISIP");
}

bool RegistrarDbRedisAsync::connect() {
	if (isConnected()) {
		LOGW("Redis already connected");
		return true;
	}

	mContext = redisAsyncConnect(mDomain.c_str(), mPort);
	mContext->data = this;
	if (mContext->err) {
		SLOGE << "Redis Connection error: " << mContext->errstr;
		redisAsyncFree(mContext);
		mContext = NULL;
		return false;
	}
	
	mSubscribeContext = redisAsyncConnect(mDomain.c_str(), mPort);
	mSubscribeContext->data = this;
	if (mSubscribeContext->err) {
		SLOGE << "Redis Connection error: " << mSubscribeContext->errstr;
		redisAsyncFree(mSubscribeContext);
		mSubscribeContext = NULL;
		return false;
	}

#ifndef WITHOUT_HIREDIS_CONNECT_CALLBACK
	redisAsyncSetConnectCallback(mContext, sConnectCallback);
	redisAsyncSetConnectCallback(mSubscribeContext, sSubscribeConnectCallback);
#endif

	redisAsyncSetDisconnectCallback(mContext, sDisconnectCallback);
	redisAsyncSetDisconnectCallback(mSubscribeContext, sSubscribeDisconnectCallback);

	if (REDIS_OK != redisSofiaAttach(mContext, mRoot)) {
		LOGE("Redis Connection error - %p", mContext);
		redisAsyncDisconnect(mContext);
		mContext = NULL;
		return false;
	}
	if (REDIS_OK != redisSofiaAttach(mSubscribeContext, mRoot)) {
		LOGE("Redis Connection error - %p", mSubscribeContext);
		redisAsyncDisconnect(mSubscribeContext);
		mSubscribeContext = NULL;
		return false;
	}

	if (!mAuthPassword.empty()) {
		redisAsyncCommand(mContext, shandleAuthReply, this, "AUTH %s", mAuthPassword.c_str());
		redisAsyncCommand(mSubscribeContext, shandleAuthReply, this, "AUTH %s", mAuthPassword.c_str());
	} else {
		getReplicationInfo();
	}
	return true;
}

bool RegistrarDbRedisAsync::disconnect() {
	LOGD("disconnect(%p)", mContext);
	bool status = false;
	if (mContext) {
		redisAsyncDisconnect(mContext);
		mContext = NULL;
		status = true;
	}
	if (mSubscribeContext) {
		// Workaround for issue https://github.com/redis/hiredis/issues/396
		redisAsyncCommand(mSubscribeContext, NULL, NULL, "UNSUBSCRIBE %s", "FLEXISIP");
		redisAsyncDisconnect(mSubscribeContext);
		mSubscribeContext = NULL;
	}
	return status;
}

void RegistrarDbRedisAsync::subscribe(const std::string &topic, const std::shared_ptr<ContactRegisteredListener> &listener) {
	RegistrarDb::subscribe(topic, listener);
	redisAsyncCommand(mSubscribeContext, sPublishCallback, NULL, "SUBSCRIBE %s", topic.c_str());
}
void RegistrarDbRedisAsync::unsubscribe(const std::string &topic) {
	RegistrarDb::unsubscribe(topic);
	redisAsyncCommand(mSubscribeContext, NULL, NULL, "UNSUBSCRIBE %s", topic.c_str());
}
void RegistrarDbRedisAsync::publish(const std::string &topic, const std::string &uid) {
	LOGD("Publish topic = %s, uid = %s", topic.c_str(), uid.c_str());
	redisAsyncCommand(mContext, NULL, NULL, "PUBLISH %s %s", topic.c_str(), uid.c_str());
}

/**
 * All three actions BIND, CLEAR and FETCH require first a retrieving of
 * the serialized contacts currently stored on the server.
 * If the redis reply is valid, the reply is forwarded to an action specific method.
 */
void RegistrarDbRedisAsync::sHandleAorGetReply(redisAsyncContext *ac, void *r, void *privdata) {
	redisReply *reply = (redisReply *)r;
	RegistrarUserData *data = (RegistrarUserData *)privdata;
	if (!reply || reply->type == REDIS_REPLY_ERROR) {
		LOGE("Redis error getting aor:%s [%lu] - %s", data->key, data->token, reply ? reply->str : "null reply");
		data->listener->onError();
		delete data;
		return;
	}

	LOGD("GOT aor:%s [%lu] --> %i bytes", data->key, data->token, reply->len);
	data->fn(ac, reply, data);
}

void RegistrarDbRedisAsync::sHandleSet(redisAsyncContext *ac, void *r, void *privdata) {
	redisReply *reply = (redisReply *)r;
	RegistrarUserData *data = (RegistrarUserData *)privdata;
	if (!reply || reply->type == REDIS_REPLY_ERROR) {
		LOGE("Redis error setting aor:%s [%lu] - %s", data->key, data->token, reply ? reply->str : "null reply");
		if( reply && string(reply->str).find("READONLY") != string::npos ){
			LOGW("Redis couldn't set the AOR because we're connected to a slave. Replying 480.");
			data->listener->onRecordFound(NULL);
		} else {
			data->listener->onError();
		}
		delete data;
		return;
	}
	LOGD("Sent updated aor:%s [%lu] success", data->key, data->token);
	data->listener->onRecordFound(&data->record);
	delete data;
}

/* Static functions that are used as callbacks to redisAsync API */

#ifndef WITHOUT_HIREDIS_CONNECT_CALLBACK
void RegistrarDbRedisAsync::sConnectCallback(const redisAsyncContext *c, int status) {
	RegistrarDbRedisAsync *zis = (RegistrarDbRedisAsync *)c->data;
	if (zis) {
		zis->onConnect(c, status);
	}
}

void RegistrarDbRedisAsync::sSubscribeConnectCallback(const redisAsyncContext *c, int status) {
	RegistrarDbRedisAsync *zis = (RegistrarDbRedisAsync *)c->data;
	if (zis) {
		zis->onSubscribeConnect(c, status);
	}
}
#endif

void RegistrarDbRedisAsync::sDisconnectCallback(const redisAsyncContext *c, int status) {
	RegistrarDbRedisAsync *zis = (RegistrarDbRedisAsync *)c->data;
	if (zis) {
		zis->onDisconnect(c, status);
	}
}

void RegistrarDbRedisAsync::sSubscribeDisconnectCallback(const redisAsyncContext *c, int status) {
	RegistrarDbRedisAsync *zis = (RegistrarDbRedisAsync *)c->data;
	if (zis) {
		zis->onSubscribeDisconnect(c, status);
	}
}

void RegistrarDbRedisAsync::sPublishCallback(redisAsyncContext *c, void *r, void *privdata) {
	redisReply *reply = (redisReply *)r;
	if (reply == NULL) return;

	if (reply->type == REDIS_REPLY_ARRAY) {
		LOGD("Publish array received: [%s, %s, %s/%i]", reply->element[0]->str, reply->element[1]->str, reply->element[2]->str, reply->element[2]->integer);
		if (reply->element[2]->str != NULL) {
			RegistrarDbRedisAsync *zis = (RegistrarDbRedisAsync *)c->data;
			if (zis) {
				zis->notifyContactListener(reply->element[1]->str, reply->element[2]->str);
			}
		}
	}
}

void RegistrarDbRedisAsync::sHandleBind(redisAsyncContext *ac, redisReply *reply, RegistrarUserData *data) {
	data->self->handleBind(reply, data);
}

void RegistrarDbRedisAsync::sHandleClear(redisAsyncContext *ac, redisReply *reply, RegistrarUserData *data) {
	data->self->handleClear(reply, data);
}

void RegistrarDbRedisAsync::sHandleFetch(redisAsyncContext *ac, redisReply *reply, RegistrarUserData *data) {
	data->self->handleFetch(reply, data);
}

void RegistrarDbRedisAsync::sHandleReplicationInfoReply(redisAsyncContext *ac, void *r, void *privdata) {
	redisReply *reply = (redisReply *)r;
	RegistrarDbRedisAsync *zis = (RegistrarDbRedisAsync *)privdata;

	if (!reply || reply->type == REDIS_REPLY_ERROR) {
		LOGE("Couldn't issue the INFO command, will try later");
		return;
	} else if (reply->str && zis) {
		zis->handleReplicationInfoReply(reply->str);
	}
}

/* this callback is called periodically to check if the current REDIS connection is valid */
void RegistrarDbRedisAsync::sHandleInfoTimer(void *unused, su_timer_t *t, void *data) {
	RegistrarDbRedisAsync *zis = (RegistrarDbRedisAsync *)data;
	if (zis && zis->mContext) {
		SLOGI << "Launching periodic INFO query on REDIS";
		zis->getReplicationInfo();
	}
}

void RegistrarDbRedisAsync::shandleAuthReply(redisAsyncContext *ac, void *r, void *privdata) {
	RegistrarDbRedisAsync *zis = (RegistrarDbRedisAsync *)privdata;
	if (zis) {
		zis->handleAuthReply((const redisReply *)r);
	}
}

/* Methods called by the callbacks */

void RegistrarDbRedisAsync::handleFetch(redisReply *reply, RegistrarUserData *data) {
	if (reply->len > 0) {
		if (!mSerializer->parse(reply->str, reply->len, &data->record)) {
			LOGE("Couldn't parse stored contacts for aor:%s : %u bytes", data->key, reply->len);
			data->listener->onError();
			delete data;
			return;
		}
		time_t now = getCurrentTime();
		data->record.clean(now);
		data->listener->onRecordFound(&data->record);
	} else {
		data->listener->onRecordFound(NULL);
	}
	delete data;
}

void RegistrarDbRedisAsync::handleClear(redisReply *reply, RegistrarUserData *data) {
	if (reply->len > 0) {
		if (!mSerializer->parse(reply->str, reply->len, &data->record)) {
			LOGE("Couldn't parse stored contacts for aor:%s : %i bytes", data->key, reply->len);
			data->listener->onError();
			delete data;
			return;
		}
		if (data->record.isInvalidRegister(data->calldId, data->csSeq)) {
			data->listener->onInvalid();
			delete data;
			return;
		}
	}
	check_redis_command(redisAsyncCommand(mContext, sHandleSet, data, "DEL aor:%s", data->key), data);
}

void RegistrarDbRedisAsync::handleBind(redisReply *reply, RegistrarUserData *data) {
	if (!mSerializer->parse(reply->str, reply->len, &data->record)) {
		LOGW("Couldn't parse stored contacts for aor:%s : %u bytes, going to erase previous value.", data->key,
			 reply->len);
	}

	if (data->record.isInvalidRegister(data->calldId, data->csSeq)) {
		SLOGD << "Cannot Bind: invalid register for call id " << data->calldId << ", CSeq " << data->csSeq << endl;
		data->listener->onInvalid();
		delete data;
		return;
	}

	time_t now = getCurrentTime();
	data->record.clean(data->sipContact, data->calldId, data->csSeq, now, data->mVersion);
	data->record.update(data->sipContact, data->path, data->globalExpire, data->calldId, data->csSeq, now, data->alias,
						data->accept, data->mUsedAsRoute);
	mLocalRegExpire->update(data->record);

	string serialized;
	mSerializer->serialize(&data->record, serialized);
	LOGD("Sending updated aor:%s [%lu] --> %u bytes", data->key, data->token, (unsigned)serialized.length());
	check_redis_command(redisAsyncCommand(mContext, sHandleSet, data, "SET aor:%s %b", data->key, serialized.data(),
										  serialized.length()),
						data);

	time_t expireat = data->record.latestExpire();
	check_redis_command(redisAsyncCommand(data->self->mContext, NULL, NULL, "EXPIREAT aor:%s %lu", data->key, expireat),
						data);
}

void RegistrarDbRedisAsync::doBind(const RegistrarDb::BindParameters &p, const shared_ptr<RegistrarDbListener> &listener) {
	const sip_accept_t *accept = p.sip.accept;
	list<string> acceptHeaders;
	while (accept != NULL) {
		acceptHeaders.push_back(accept->ac_type);
		accept = accept->ac_next;
	}

	RegistrarUserData *data = new RegistrarUserData(this, p.sip.from, p.sip.contact, p.sip.call_id, p.sip.cs_seq,
													p.sip.path, p.alias, p.version, listener, sHandleBind);
	data->globalExpire = p.global_expire;
	data->accept = acceptHeaders;
	data->mUsedAsRoute = p.usedAsRoute;
	if (!isConnected() && !connect()) {
		LOGE("Not connected to redis server");
		data->listener->onError();
		delete data;
		return;
	}
	if (errorOnTooMuchContactInBind(p.sip.contact, data->key, listener)) {
		data->listener->onError();
		delete data;
		return;
	}

	LOGD("Binding aor:%s [%lu]", data->key, data->token);
	check_redis_command(redisAsyncCommand(mContext, sHandleAorGetReply, data, "GET aor:%s", data->key), data);
}

void RegistrarDbRedisAsync::doClear(const sip_t *sip, const shared_ptr<RegistrarDbListener> &listener) {
	RegistrarUserData *data =
		new RegistrarUserData(this, sip->sip_from->a_url, sip->sip_contact, sip->sip_call_id->i_id,
							  sip->sip_cseq->cs_seq, listener, sHandleClear);
	if (!isConnected() && !connect()) {
		LOGE("Not connected to redis server");
		data->listener->onError();
		delete data;
		return;
	}
	LOGD("Clearing aor:%s [%lu]", data->key, data->token);
	mLocalRegExpire->remove(data->key);
	check_redis_command(redisAsyncCommand(mContext, sHandleAorGetReply, data, "GET aor:%s", data->key), data);
}

void RegistrarDbRedisAsync::doFetch(const url_t *url, const shared_ptr<RegistrarDbListener> &listener) {
	RegistrarUserData *data = new RegistrarUserData(this, url, listener, sHandleFetch);
	if (!isConnected() && !connect()) {
		LOGE("Not connected to redis server");
		data->listener->onError();
		delete data;
		return;
	}
	LOGD("Fetching aor:%s [%lu]", data->key, data->token);
	check_redis_command(redisAsyncCommand(mContext, sHandleAorGetReply, data, "GET aor:%s", data->key), data);
}
