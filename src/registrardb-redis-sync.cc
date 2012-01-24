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

#include <sofia-sip/sip_protos.h>

using namespace::std;

RecordSerializer *RecordSerializer::sInstance=NULL;
RecordSerializer *RecordSerializer::get() {
	if (!sInstance) {
		ConfigStruct *registrar=ConfigManager::get()->getRoot()->get<ConfigStruct>("module::Registrar");
		string name=registrar->get<ConfigString>("redis-record-serializer")->read();
		if (name == "c") {
			sInstance = new RecordSerializerC();
		} else if (name == "json") {
			sInstance = new RecordSerializerJson();
#if ENABLE_PROTOBUF
		} else if (name == "protobuf") {
			sInstance = new RecordSerializerPb();
#endif
		} else {
			LOGF("Unsupported record serializer: %s", name.c_str());
		}
	}
	return sInstance;
}


string RegistrarDbRedisSync::sDomain="";
string RegistrarDbRedisSync::sAuthPassword="";
int RegistrarDbRedisSync::sPort=0;
int RegistrarDbRedisSync::sTimeout=0;
RegistrarDbRedisSync::RegistrarDbRedisSync():mContext(NULL){
	mSerializer=RecordSerializer::get();
	ConfigStruct *registrar=ConfigManager::get()->getRoot()->get<ConfigStruct>("module::Registrar");
	sDomain=registrar->get<ConfigString>("redis-server-domain")->read();
	sPort=registrar->get<ConfigInt>("redis-server-port")->read();
	sTimeout=registrar->get<ConfigInt>("redis-server-timeout")->read();
	sAuthPassword=registrar->get<ConfigString>("redis-auth-password")->read();
}

RegistrarDbRedisSync::~RegistrarDbRedisSync(){
	if (mContext) redisFree(mContext);
}



bool RegistrarDbRedisSync::isConnected() {
	return mContext && REDIS_CONNECTED == (mContext->flags & REDIS_CONNECTED);
}

bool RegistrarDbRedisSync::connect(){
	if (isConnected()) {
		LOGW("Redis already connected");
		return true;
	}
	int seconds=sTimeout/1000;
    struct timeval timeout = {seconds, sTimeout-seconds};
    mContext = redisConnectWithTimeout(sDomain.c_str(), sPort, timeout);
    if (mContext->err) {
        LOGE("Redis Connection error: %s", mContext->errstr);
        redisFree(mContext);
        mContext=NULL;
        return false;
    }

    if (!sAuthPassword.empty()){

    	redisReply *reply = (redisReply*) redisCommand(mContext, "AUTH %s", sAuthPassword.c_str());
    	if (reply->type == REDIS_REPLY_ERROR) {
    		LOGE("Could'nt authenticate with redis server");
    	  	redisFree(mContext);
    	  	mContext=NULL;
    	   	return false;
    	}
    }

    return true;
}



void RegistrarDbRedisSync::bind(const sip_t *sip, const char* route, int globalExpire, RegistrarDbListener *listener){
	char key[AOR_KEY_SIZE]={0};
	defineKeyFromUrl(key,AOR_KEY_SIZE-1, sip->sip_from->a_url);

	if (errorOnTooMuchContactInBind(sip,key,listener)){
		listener->onError();
		return;
	}

	if (!isConnected() && !connect()) {
		listener->onError();
		return;
	}

    redisReply *reply = (redisReply*) redisCommand(mContext,"GET aor:%s",key);
    if (reply->type == REDIS_REPLY_ERROR) {
    	LOGE("Redis error getting aor:%s - %s", key, reply->str);
    	listener->onError();
    	return;
    }
    LOGD("GOT aor:%s --> %s", key,reply->str);
    Record r;
    mSerializer->parse(reply->str, reply->len, &r);
    freeReplyObject(reply);

    if (r.isInvalidRegister(sip->sip_call_id->i_id, sip->sip_cseq->cs_seq)){
    	listener->onInvalid();
    	return;
    }

	time_t now=time(NULL);
    r.clean(sip->sip_contact, sip->sip_call_id->i_id, sip->sip_cseq->cs_seq, now);
	r.bind(sip->sip_contact, route, globalExpire, sip->sip_call_id->i_id, sip->sip_cseq->cs_seq, now);

	std::string updatedAorString;
	mSerializer->serialize(&r, updatedAorString);

	reply = (redisReply*) redisCommand(mContext,"SET aor:%s %s",key, updatedAorString.c_str());
    if (reply->type == REDIS_REPLY_ERROR) {
    	LOGE("Redis error setting aor:%s with %s - %s", key, updatedAorString.c_str(), reply->str);
    	listener->onError();
    	freeReplyObject(reply);
    	return;
    }
	LOGD("Sent updated aor:%s --> %s", key,updatedAorString.c_str());
	freeReplyObject(reply);


	listener->onRecordFound(&r);
}


void RegistrarDbRedisSync::clear(const sip_t *sip, RegistrarDbListener *listener){
	char key[AOR_KEY_SIZE]={0};
	defineKeyFromUrl(key,AOR_KEY_SIZE-1, sip->sip_from->a_url);

	if (!isConnected() && !connect()) {
		listener->onError();
		return;
	}

    redisReply *reply = (redisReply*) redisCommand(mContext,"GET aor:%s",key);
    if (reply->type == REDIS_REPLY_ERROR) {
    	LOGE("Redis error getting aor:%s - %s", key, reply->str);
    	listener->onError();
    	return;
    }
    LOGD("GOT aor:%s --> %s", key,reply->str);

    if (reply->str > 0) {
    	Record r;
    	mSerializer->parse(reply->str, reply->len, &r);
    	if (r.isInvalidRegister(sip->sip_call_id->i_id, sip->sip_cseq->cs_seq)){
        	listener->onInvalid();
            freeReplyObject(reply);
        	return;
        }
    }

    freeReplyObject(reply);


	reply = (redisReply*) redisCommand(mContext,"SET aor:%s %s",key, "");
    if (reply->type == REDIS_REPLY_ERROR) {
    	LOGE("Redis error clearing aor:%s - %s", key, reply->str);
    	listener->onError();
    	freeReplyObject(reply);
    	return;
    }
	LOGD("Cleared aor:%s", key);
	freeReplyObject(reply);

	listener->onRecordFound(NULL);
}

void RegistrarDbRedisSync::fetch(const url_t *url, RegistrarDbListener *listener){
	char key[AOR_KEY_SIZE]={0};
	defineKeyFromUrl(key,AOR_KEY_SIZE-1, url);

	if (!isConnected() && !connect()) {
		listener->onError();
		return;
	}

    redisReply *reply = (redisReply*) redisCommand(mContext,"GET aor:%s",key);
    if (reply->type == REDIS_REPLY_ERROR) {
    	LOGE("Redis error getting aor:%s - %s", key, reply->str);
    	listener->onError();
    	return;
    }
    LOGD("GOT aor:%s --> %s", key,reply->str);
    Record r;
    mSerializer->parse(reply->str, reply->len, &r);
    freeReplyObject(reply);

    time_t now=time(NULL);
    r.clean(now);

    listener->onRecordFound(&r);
}
