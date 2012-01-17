/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2012  Belledonne Communications SARL.
    Author: Guillaume Beraudo

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

#include "configmanager.hh"

#include <hiredis/hiredis.h>

#include "registrardb-redis-sofia-event.h"
#include <sofia-sip/sip_protos.h>

using namespace::std;

#define ERROR data->listener->onError(); delete data; return;

string RegistrarDbRedisAsync::sDomain="";
int RegistrarDbRedisAsync::sPort=0;
int RegistrarDbRedisAsync::sTimeout=0;
RegistrarDbRedisAsync::RegistrarDbRedisAsync(Agent *ag):mContext(NULL),mRoot(ag->getRoot()){
	mSerializer=RecordSerializer::get();
	ConfigStruct *registrar=ConfigManager::get()->getRoot()->get<ConfigStruct>("module::Registrar");
	sDomain=registrar->get<ConfigString>("redis-server-domain")->read();
	sPort=registrar->get<ConfigInt>("redis-server-port")->read();
	sTimeout=registrar->get<ConfigInt>("redis-server-timeout")->read();
}

RegistrarDbRedisAsync::~RegistrarDbRedisAsync(){
	if (mContext) {
		redisAsyncDisconnect(mContext);
	}
}




void RegistrarDbRedisAsync::connectCallback(const redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        LOGE("Couldn't connect to redis: %s", c->errstr);
        return;
    }
    LOGD("Connected... %p", c);
}

void RegistrarDbRedisAsync::disconnectCallback(const redisAsyncContext *c, int status) {
	RegistrarDbRedisAsync *zis=(RegistrarDbRedisAsync *) c->data;
	zis->mContext=NULL;
	if (status != REDIS_OK) {
		LOGE("Redis disconnection message: %s", c->errstr);
		return;
	}
	LOGD("Disconnected %p...", c);
}

bool RegistrarDbRedisAsync::isConnected() {
	return mContext != NULL;
}

bool RegistrarDbRedisAsync::connect(){
	if (isConnected()) {
		LOGW("Redis already connected");
		return true;
	}

    mContext = redisAsyncConnect(sDomain.c_str(), sPort);
    mContext->data=this;
    if (mContext->err) {
        LOGE("Redis Connection error: %s", mContext->errstr);
        redisAsyncFree(mContext);
        mContext=NULL;
        return false;
    }

    redisAsyncSetConnectCallback(mContext, connectCallback);
    redisAsyncSetDisconnectCallback(mContext, disconnectCallback);

    if (REDIS_OK != redisSofiaAttach(mContext, mRoot)){
    	LOGE("Redis Connection error");
    	redisAsyncDisconnect(mContext);
    	mContext=NULL;
    	return false;
    }

    return true;
}

unsigned long RegistrarDbRedisAsync::getToken(){
	if (mToken == LONG_MAX) {
		mToken=0;
	}
	return mToken++;
}


typedef void (forwardFn)(redisAsyncContext*, redisReply*,RegistrarDbRedisAsync::RegistrarUserData *);

typedef struct RegistrarDbRedisAsync::RegistrarUserData {
	RegistrarDbRedisAsync *self;
	char key[AOR_KEY_SIZE];
	forwardFn *fn;
	unsigned long token;
	const sip_t *sip;
	RegistrarDbListener *listener;
	Record record;
	int globalExpire;
	char *route;

	RegistrarUserData(RegistrarDbRedisAsync *self, const sip_t *sip, const char *route, RegistrarDbListener *listener, forwardFn *fn):
		self(self),fn(fn),token(0),sip(sip),listener(listener),globalExpire(0),route(NULL){
		defineKeyFromUrl(key,AOR_KEY_SIZE-1, sip->sip_from->a_url);
		if (route) this->route=strdup(route);
	}
	RegistrarUserData(RegistrarDbRedisAsync *self, const sip_t *sip, RegistrarDbListener *listener, forwardFn *fn):
		self(self),fn(fn),token(0),sip(sip),listener(listener),globalExpire(0),route(NULL){
		defineKeyFromUrl(key,AOR_KEY_SIZE-1, sip->sip_from->a_url);
	}
	RegistrarUserData(RegistrarDbRedisAsync *self, const url_t *url, RegistrarDbListener *listener, forwardFn *fn):
		self(self),fn(fn),token(0),sip(NULL),listener(listener),globalExpire(0),route(NULL){
		defineKeyFromUrl(key,AOR_KEY_SIZE-1, url);
	}
	~RegistrarUserData(){
		if (route) free(route);
	}
} RegistrarUserData;


/**
 * All three actions BIND, CLEAR and FETCH require first a retrieving of
 * the serialized contacts currently stored on the server.
 * If the redis reply is valid, the reply is forwarded to an action specific method.
 */
void RegistrarDbRedisAsync::sHandleAorGetReply(redisAsyncContext* ac, void *r, void *privdata){
	redisReply *reply = (redisReply *)r;
	RegistrarUserData *data=(RegistrarUserData *)privdata;
	if (!reply || reply->type == REDIS_REPLY_ERROR){
		LOGE("Redis error getting aor:%s [%lu] - %s", data->key, data->token, reply?reply->str:"null reply");
		ERROR
	}

	LOGD("GOT aor:%s [%lu] --> %i bytes", data->key,data->token, reply->len);
	data->fn(ac,reply,data);
}

void RegistrarDbRedisAsync::sHandleSet(redisAsyncContext* ac, void *r, void *privdata){
	redisReply *reply = (redisReply *)r;
	RegistrarUserData *data=(RegistrarUserData *)privdata;
    if (!reply || reply->type == REDIS_REPLY_ERROR) {
    	LOGE("Redis error setting aor:%s [%lu] - %s", data->key, data->token, reply?reply->str:"null reply");
		ERROR
    }
	LOGD("Sent updated aor:%s [%lu] success", data->key,data->token);
	data->listener->onRecordFound(&data->record);
	delete data;
}




void RegistrarDbRedisAsync::sHandleBind(redisAsyncContext* ac, redisReply *reply, RegistrarUserData *data){
	data->self->handleBind(reply,data);
}

void RegistrarDbRedisAsync::sHandleClear(redisAsyncContext* ac, redisReply *reply, RegistrarUserData *data){
	data->self->handleClear(reply,data);
}

void RegistrarDbRedisAsync::sHandleFetch(redisAsyncContext* ac, redisReply *reply, RegistrarUserData *data){
	data->self->handleFetch(reply,data);
}






void RegistrarDbRedisAsync::handleFetch(redisReply *reply, RegistrarUserData *data){
	if (!mSerializer->parse(reply->str, reply->len, &data->record)) {
		LOGE("Couldn't parse stored contacts for aor:%s : %u bytes", data->key, reply->len);
		ERROR
	}

	time_t now=time(NULL);
	data->record.clean(now);

	data->listener->onRecordFound(&data->record);
	delete data;
}




void RegistrarDbRedisAsync::handleClear(redisReply *reply, RegistrarUserData *data){
	const sip_t *sip=data->sip;

    if (reply->str > 0) {
    	if (!mSerializer->parse(reply->str, reply->len, &data->record)) {
    		LOGE("Couldn't parse stored contacts for aor:%s : %i bytes", data->key, reply->len);
    		ERROR
    	}
    	if (data->record.isInvalidRegister(sip->sip_call_id->i_id, sip->sip_cseq->cs_seq)){
        	data->listener->onInvalid();
        	delete data;
        	return;
        }
    }

	redisAsyncCommand(mContext, sHandleSet, data,"SET aor:%s %s",data->key, "");
}




void RegistrarDbRedisAsync::handleBind(redisReply *reply, RegistrarUserData *data){
	const sip_t *sip=data->sip;
	if (!mSerializer->parse(reply->str, reply->len, &data->record)) {
		LOGE("Couldn't parse stored contacts for aor:%s : %u bytes", data->key, reply->len);
		ERROR
	}


	if (data->record.isInvalidRegister(sip->sip_call_id->i_id, sip->sip_cseq->cs_seq)){
		data->listener->onInvalid();
		delete data;
		return;
	}

	time_t now=time(NULL);
	data->record.clean(sip->sip_contact, sip->sip_call_id->i_id, sip->sip_cseq->cs_seq, now);
	data->record.bind(sip->sip_contact, data->route, data->globalExpire, sip->sip_call_id->i_id, sip->sip_cseq->cs_seq, now);

	std::string serialized;
	mSerializer->serialize(&data->record, serialized);
	LOGD("Sending updated aor:%s [%lu] --> %u bytes", data->key,data->token,(unsigned)serialized.length());
	redisAsyncCommand(mContext, sHandleSet, data,"SET aor:%s %b",data->key, serialized.data(), serialized.length());
}














void RegistrarDbRedisAsync::bind(const sip_t *sip, const char *route, int globalExpire, RegistrarDbListener *listener){
	RegistrarUserData *data=new RegistrarUserData(this,sip,route,listener,sHandleBind);
	data->globalExpire=globalExpire;
	if (!isConnected() && !connect()) {
		LOGE("Not connected to redis server");
		ERROR
	}
	if (errorOnTooMuchContactInBind(sip,data->key,listener)){
		ERROR
	}

	LOGD("Binding aor:%s [%lu]", data->key, data->token);
	redisAsyncCommand(mContext, sHandleAorGetReply,data,"GET aor:%s",data->key);
}


void RegistrarDbRedisAsync::clear(const sip_t *sip, RegistrarDbListener *listener){
	RegistrarUserData *data=new RegistrarUserData(this,sip,listener,sHandleClear);
	if (!isConnected() && !connect()) {
		LOGE("Not connected to redis server");
		ERROR
	}
	LOGD("Clearing aor:%s [%lu]", data->key, data->token);
	redisAsyncCommand(mContext, sHandleAorGetReply,data,"GET aor:%s",data->key);
}




void RegistrarDbRedisAsync::fetch(const url_t *url, RegistrarDbListener *listener){
	RegistrarUserData *data=new RegistrarUserData(this,url,listener,sHandleFetch);
	if (!isConnected() && !connect()) {
		LOGE("Not connected to redis server");
		ERROR
	}
	LOGD("Fetching aor:%s [%lu]", data->key, data->token);
	redisAsyncCommand(mContext, sHandleAorGetReply,data,"GET aor:%s",data->key);
}
