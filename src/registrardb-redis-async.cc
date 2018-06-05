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

RegistrarUserData::RegistrarUserData(RegistrarDbRedisAsync *s, const url_t *url, shared_ptr<ContactUpdateListener> listener)
	: self(s), listener(listener), record(url), token(0), mUpdateExpire(false), mRetryCount(0), mGruu(""), mIsUnregister(false) {
	
}
RegistrarUserData::~RegistrarUserData() {
	
}

/******
 * RegistrarDbRedisAsync class
 */

RegistrarDbRedisAsync::RegistrarDbRedisAsync(Agent *ag, RedisParameters params)
	: RegistrarDb(ag), mContext(NULL), mSubscribeContext(NULL),
	  mDomain(params.domain), mAuthPassword(params.auth), mPort(params.port), mTimeout(params.timeout), mRoot(ag->getRoot()),
	  mReplicationTimer(NULL), mSlaveCheckTimeout(params.mSlaveCheckTimeout) {
	mSerializer = RecordSerializer::get();
	mCurSlave = 0;
}

RegistrarDbRedisAsync::RegistrarDbRedisAsync(const string &preferredRoute, su_root_t *root, RecordSerializer *serializer, RedisParameters params)
	: RegistrarDb(NULL), mContext(NULL), mSubscribeContext(NULL),
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
	LOGD("REDIS Disconnected %p...", c);
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
	LOGD("REDIS Connected... %p", c);
}

void RegistrarDbRedisAsync::onSubscribeDisconnect(const redisAsyncContext *c, int status) {
	if (mSubscribeContext != NULL && mSubscribeContext != c) {
		LOGE("Redis subscribe context %p disconnected, but current context is %p", c, mSubscribeContext);
		return;
	}

	mSubscribeContext = NULL;
	LOGD("Disconnected subscribe context %p...", c);
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
	LOGD("REDIS Connection done for subscribe channel %p", c);
	if (!mContactListenersMap.empty()){
		LOGD("Now re-subscribing all topics we had before being disconnected.");
		subscribeAll();
	}
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
	vector<RedisHost> newSlaves;

	try {
		int slaveCount = atoi(redisReply.at("connected_slaves").c_str());
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
	} catch (const out_of_range &) {}

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

/*this function is invoked after a redis disconnection on the subscribe channel, so that all topics we are interested in are re-subscribed.*/
void RegistrarDbRedisAsync::subscribeAll(){
	for(auto it = mContactListenersMap.begin(); it != mContactListenersMap.end(); ++it){
		subscribeTopic((*it).first);
	}
}

void RegistrarDbRedisAsync::subscribeTopic(const string &topic){
	LOGD("Sending SUBSCRIBE command to redis for topic '%s'", topic.c_str());
	redisAsyncCommand(mSubscribeContext, sPublishCallback, NULL, "SUBSCRIBE %s", topic.c_str());
}

void RegistrarDbRedisAsync::subscribe(const std::string &topic, const std::shared_ptr<ContactRegisteredListener> &listener) {
	RegistrarDb::subscribe(topic, listener);
	subscribeTopic(topic);
}
void RegistrarDbRedisAsync::unsubscribe(const std::string &topic) {
	RegistrarDb::unsubscribe(topic);
	redisAsyncCommand(mSubscribeContext, NULL, NULL, "UNSUBSCRIBE %s", topic.c_str());
}
void RegistrarDbRedisAsync::publish(const std::string &topic, const std::string &uid) {
	LOGD("Publish topic = %s, uid = %s", topic.c_str(), uid.c_str());
	redisAsyncCommand(mContext, NULL, NULL, "PUBLISH %s %s", topic.c_str(), uid.c_str());
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
		LOGD("Publish array received: [%s, %s, %s/%i]", reply->element[0]->str, reply->element[1]->str, reply->element[2]->str, (int)reply->element[2]->integer);
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

void RegistrarDbRedisAsync::sHandleMigration(redisAsyncContext *ac, redisReply *reply, RegistrarUserData *data) {
	data->self->handleMigration(reply, data);
}

void RegistrarDbRedisAsync::sHandleRecordMigration(redisAsyncContext *ac, redisReply *reply, RegistrarUserData *data) {
	data->self->handleRecordMigration(reply, data);
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

void RegistrarDbRedisAsync::serializeAndSendToRedis(RegistrarUserData *data, forwardFn *forward_fn) {
	const char *key = data->record.getKey().c_str();

	int argc = 2; // HMSET key
	string cmd = "HMSET";

	const auto &contacts = data->record.getExtendedContacts();
	argc += contacts.size() * 2;

	const char** argv = new const char*[argc];
	size_t* argvlen = new size_t[argc];

	argv[0] = cmd.c_str();
	argvlen[0] = strlen(argv[0]);

	int namespace_len = strlen(key) + 4; // 4 is fs: length + \0
	char record_namespace[namespace_len];
	snprintf(record_namespace, namespace_len, "fs:%s", key);
	argv[1] = record_namespace;
	argvlen[1] = strlen(argv[1]);

	int i = 2;
	for (auto it = contacts.begin(); it != contacts.end(); ++it) {
		shared_ptr<ExtendedContact> ec = (*it);

		argv[i] = strdup(ec->getUniqueId().c_str());
		argvlen[i] = strlen(argv[i]);
		i += 1;

		string contact = ec->serializeAsUrlEncodedParams();
		argv[i] = strdup(contact.c_str());
		argvlen[i] = strlen(argv[i]);
		i += 1;
	}

	data->mUpdateExpire = true;
	LOGD("Binding fs:%s [%lu], %lu contacts in record", key, data->token, (unsigned long)contacts.size());
	check_redis_command(redisAsyncCommandArgv(mContext, (void (*)(redisAsyncContext*, void*, void*))forward_fn, 
		data, argc, argv, argvlen), data);

	for (i = 2; i < argc; i++) {
		free((char *)argv[i]);
	}
	delete[] argv;
	delete[] argvlen;
}

/* Methods called by the callbacks */

void RegistrarDbRedisAsync::handleBind(redisReply *reply, RegistrarUserData *data) {
	const char *key = data->record.getKey().c_str();

	if ((!reply || reply->type == REDIS_REPLY_ERROR) && (data->mRetryCount < 2)) {
		LOGE("Error while updating record fs:%s [%lu] hashmap in redis, trying again", key, data->token);
		data->mRetryCount += 1;
		serializeAndSendToRedis(data, sHandleBind);
	} else {
		data->mRetryCount = 0;
		LOGD("Binding ok, fetching fs:%s [%lu]", key, data->token);
		check_redis_command(redisAsyncCommand(mContext, (void (*)(redisAsyncContext*, void*, void*))sHandleFetch, data, "HGETALL fs:%s", key), data);
	}
}

static string extractUniqueId(Record r, sip_contact_t *contact) {
	while (contact) {
		string lineValue = r.extractUniqueId(contact);
		if (!lineValue.empty()) {
			return lineValue;
		}
		contact = contact->m_next;
	}
	return "";
}

void RegistrarDbRedisAsync::doBind(const url_t *ifrom, sip_contact_t *icontact, const char *iid, uint32_t iseq,
					  const sip_path_t *ipath, list<string> acceptHeaders, bool usedAsRoute, int expire, int alias, int version, 
					  const shared_ptr<ContactUpdateListener> &listener) {
	// Update the AOR Hashmap using HSET
	// If there is an error, try again
	// Once it is done, fetch all the contacts in the AOR and call the onRecordFound of the listener

	RegistrarUserData *data = new RegistrarUserData(this, ifrom, listener);
	time_t now = getCurrentTime();

	data->record.update(icontact, ipath, expire, iid, iseq, now, alias, acceptHeaders, usedAsRoute, data->listener);
	mLocalRegExpire->update(data->record);

	if (!isConnected() && !connect()) {
		LOGE("Not connected to redis server");
		if (data->listener) data->listener->onError();
		delete data;
		return;
	}
	const char *mss_expires = RegistrarDb::get()->getMessageExpires(icontact->m_params).c_str();
	int message_expires = mss_expires ? atoi(mss_expires) : 0;
	if (expire > 0 || message_expires > 0) {
		serializeAndSendToRedis(data, sHandleBind);
	} else {
		const char *key = data->record.getKey().c_str();
		string uid = extractUniqueId(data->record, icontact);
		data->mIsUnregister = true;
		check_redis_command(redisAsyncCommand(mContext, (void (*)(redisAsyncContext*, void*, void*))sHandleBind, 
			data, "HDEL fs:%s %s", key, uid.c_str()), data);
	}
}

void RegistrarDbRedisAsync::handleClear(redisReply *reply, RegistrarUserData *data) {
	const char *key = data->record.getKey().c_str();

	if (!reply || reply->type == REDIS_REPLY_ERROR) {
		LOGE("Redis error setting fs:%s [%lu] - %s", key, data->token, reply ? reply->str : "null reply");
		if (reply && string(reply->str).find("READONLY") != string::npos) {
			LOGW("Redis couldn't set the AOR because we're connected to a slave. Replying 480.");
			if (data->listener) data->listener->onRecordFound(NULL);
		} else {
			if (data->listener) data->listener->onError();
		}
	} else {
		LOGD("Clearing fs:%s [%lu] success", key, data->token);
		if (data->listener) data->listener->onRecordFound(&data->record);
	}
	delete data;
}

void RegistrarDbRedisAsync::doClear(const sip_t *sip, const shared_ptr<ContactUpdateListener> &listener) {
	// Delete the AOR Hashmap using DEL
	// Once it is done, fetch all the contacts in the AOR and call the onRecordFound of the listener ?
	RegistrarUserData *data = new RegistrarUserData(this, sip->sip_from->a_url, listener);

	if (!isConnected() && !connect()) {
		LOGE("Not connected to redis server");
		if (data->listener) data->listener->onError();
		delete data;
		return;
	}

	const char *key = data->record.getKey().c_str();
	LOGD("Clearing fs:%s [%lu]", key, data->token);
	mLocalRegExpire->remove(key);
	check_redis_command(redisAsyncCommand(mContext, (void (*)(redisAsyncContext*, void*, void*))sHandleClear, 
		data, "DEL fs:%s", key), data);
}

void RegistrarDbRedisAsync::handleFetch(redisReply *reply, RegistrarUserData *data) {
	const char *key = data->record.getKey().c_str();

	if (!reply || reply->type == REDIS_REPLY_ERROR) {
		LOGE("Redis error: %s", reply ? reply->str : "null reply");
		if (data->listener) data->listener->onError();
		delete data;
	} else if (reply->type == REDIS_REPLY_ARRAY) {
		// This is the most common scenario: we want all contacts inside the record
		LOGD("GOT fs:%s [%lu] --> %lu contacts", key, data->token, (reply->elements / 2));
		if (reply->elements > 0) {
			for (size_t i = 0; i < reply->elements; i+=2) {
				// Elements list is twice the size of the contacts list because the key is an element of the list itself
				redisReply *element = reply->element[i];
				const char *uid = element->str;
				element = reply->element[i+1];
				const char *contact = element->str;
				LOGD("Parsing contact %s => %s", uid, contact);
				if (!data->record.updateFromUrlEncodedParams(key, uid, contact)) {
					LOGD("Record %s seems to have an outdated contact %s, remove it from redis", key, uid);
					check_redis_command(redisAsyncCommand(data->self->mContext, NULL, NULL, "HDEL fs:%s %s", key, uid), data);
				}
			}
			data->record.applyMaxAor();

			for (auto it = data->record.getContactsToRemove().begin(); it != data->record.getContactsToRemove().end(); ++it) {
				// Remove from REDIS contacts removed from record
				const char *uid = (*it)->mUniqueId.c_str();
				LOGD("Record %s has too many contacts, removing %s from redis", key, uid);
				check_redis_command(redisAsyncCommand(data->self->mContext, NULL, NULL, "HDEL fs:%s %s", key, uid), data);
			}
			data->record.cleanContactsToRemoveList();

			if (data->mUpdateExpire) {
				time_t expireat = data->record.latestExpire();
				check_redis_command(redisAsyncCommand(data->self->mContext, NULL, NULL, "EXPIREAT fs:%s %lu", key, expireat), data);
			}

			time_t now = getCurrentTime();
			data->record.clean(now, data->listener);
			if (data->listener) data->listener->onRecordFound(&data->record);
			delete data;
		} else {
			// We haven't found the record in redis, trying to find an old record
			LOGD("Record fs:%s not found, trying aor:%s", key, key);
			check_redis_command(redisAsyncCommand(mContext, (void (*)(redisAsyncContext*, void*, void*))sHandleRecordMigration, 
				data, "GET aor:%s", key), data);
		}
	} else {
		// This is only when we want a contact matching a given gruu
		const char *gruu = data->mGruu.c_str();
		if (reply->len > 0) {
			LOGD("GOT fs:%s [%lu] for gruu %s --> %s", key, data->token, gruu, reply->str);
			data->record.updateFromUrlEncodedParams(key, gruu, reply->str);
			time_t now = getCurrentTime();
			data->record.clean(now, data->listener);
			if (data->listener) data->listener->onRecordFound(&data->record);
		} else {
			LOGD("Contact matching gruu %s in record fs:%s not found", gruu, key);
			if (data->listener) data->listener->onRecordFound(NULL);
		}
		delete data;
	}
}

void RegistrarDbRedisAsync::doFetch(const url_t *url, const shared_ptr<ContactUpdateListener> &listener) {
	// fetch all the contacts in the AOR (HGETALL) and call the onRecordFound of the listener
	RegistrarUserData *data = new RegistrarUserData(this, url, listener);

	if (!isConnected() && !connect()) {
		LOGE("Not connected to redis server");
		if (data->listener) data->listener->onError();
		delete data;
		return;
	}

	const char *key = data->record.getKey().c_str();
	LOGD("Fetching fs:%s [%lu]", key, data->token);
	check_redis_command(redisAsyncCommand(mContext, (void (*)(redisAsyncContext*, void*, void*))sHandleFetch, 
		data, "HGETALL fs:%s", key), data);
}

void RegistrarDbRedisAsync::doFetchForGruu(const url_t *url, const string &gruu, const shared_ptr<ContactUpdateListener> &listener) {
	// fetch only the contact in the AOR (HGET) and call the onRecordFound of the listener
	RegistrarUserData *data = new RegistrarUserData(this, url, listener);
	data->mGruu = gruu;
	
	if (!isConnected() && !connect()) {
		LOGE("Not connected to redis server");
		if (data->listener) data->listener->onError();
		delete data;
		return;
	}

	const char *key = data->record.getKey().c_str();
	const char *field = gruu.c_str();
	LOGD("Fetching fs:%s [%lu] contact matching gruu %s", key, data->token, field);
	check_redis_command(redisAsyncCommand(mContext, (void (*)(redisAsyncContext*, void*, void*))sHandleFetch, 
		data, "HGET fs:%s %s", key, field), data);
}

/*
 * The following code is to migrate a redis database to the new way
 */

void RegistrarDbRedisAsync::handleRecordMigration(redisReply *reply, RegistrarUserData *data) {
	if (!reply || reply->type == REDIS_REPLY_ERROR) {
		LOGE("Redis error: %s", reply ? reply->str : "null reply");
		if (data->listener) data->listener->onRecordFound(NULL); 
	} else {
		if (reply->len > 0) {
			if (!mSerializer->parse(reply->str, reply->len, &data->record)) {
				LOGE("Couldn't parse stored contacts for aor:%s : %u bytes", data->record.getKey().c_str(), (unsigned int)reply->len);
				if (data->listener) data->listener->onRecordFound(NULL); 
			} else {
				LOGD("Parsing stored contacts for aor:%s successful", data->record.getKey().c_str());
				serializeAndSendToRedis(data, sHandleMigration);
				return;
			}
		} else {
			// This is a workaround required in case of unregister (expire set to 0) because
			// if there is only one entry, it will be deleted first so the fetch will come back empty
			// and flexisip will answer 480 instead of 200.
			if (data->listener) data->listener->onRecordFound(data->mIsUnregister ? &data->record : NULL); 
		}
	}
	delete data;
}

void RegistrarDbRedisAsync::handleMigration(redisReply *reply, RegistrarUserData *data) {
	if (!reply || reply->type == REDIS_REPLY_ERROR) {
		LOGE("Redis error: %s", reply ? reply->str : "null reply");
	} else if (reply->type == REDIS_REPLY_ARRAY) {
		LOGD("Fetching all previous records success: %lu record(s) found", (unsigned long)reply->elements);

		su_home_t home;
		su_home_init(&home);
		for (size_t i = 0; i < reply->elements; i++) {
			redisReply *element = reply->element[i];
			url_t *url = url_make(&home, element->str);
			RegistrarUserData *new_data = new RegistrarUserData(this, url, NULL);
			LOGD("Fetching previous record: %s", element->str);
			check_redis_command(redisAsyncCommand(mContext, (void (*)(redisAsyncContext*, void*, void*))sHandleRecordMigration, 
				new_data, "GET %s", element->str), new_data);
		}
		su_home_deinit(&home);
	} else {
		LOGD("Record aor:%s successfully migrated", data->record.getKey().c_str());
		if (data->listener) data->listener->onRecordFound(&data->record); 
		/*If we want someday to remove the previous record, uncomment the following and comment the delete data above
		check_redis_command(redisAsyncCommand(mContext, (void (*)(redisAsyncContext*, void*, void*))sHandleClear, 
			data, "DEL aor:%s", data->record.getKey().c_str()), data);*/
	}
	delete data;
}

void RegistrarDbRedisAsync::doMigration() {
	if (!isConnected() && !connect()) {
		LOGE("Not connected to redis server");
		return;
	}

	LOGD("Fetching previous record(s)");
	RegistrarUserData *data = new RegistrarUserData(this, NULL, NULL);
	check_redis_command(redisAsyncCommand(mContext, (void (*)(redisAsyncContext*, void*, void*))sHandleMigration, 
		data, "KEYS aor:*"), data);
}
