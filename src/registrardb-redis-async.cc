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
#define chk_redis_err(cmd)  if (REDIS_ERR == (cmd)) { LOGD("Redis error") ; ERROR }

RegistrarDbRedisAsync::RegistrarDbRedisAsync ( Agent *ag, RedisParameters params )
:RegistrarDb ( ag->getPreferredRoute() ),mContext ( NULL ), sDomain(params.domain),
sAuthPassword(params.auth), sPort(params.port), sTimeout(params.timeout) ,mRoot ( ag->getRoot() ){
	mSerializer=RecordSerializer::get();
}

RegistrarDbRedisAsync::~RegistrarDbRedisAsync()
{
	if ( mContext ) {
		redisAsyncDisconnect ( mContext );
	}
}


#ifndef WITHOUT_HIREDIS_CONNECT_CALLBACK
void RegistrarDbRedisAsync::connectCallback ( const redisAsyncContext *c, int status )
{
	if ( status != REDIS_OK ) {
		LOGE ( "Couldn't connect to redis: %s", c->errstr );
		RegistrarDbRedisAsync *zis= ( RegistrarDbRedisAsync * ) c->data;
		zis->mContext=NULL;
		return;
	}
	LOGD ( "Connected... %p", c );
}
#endif

void RegistrarDbRedisAsync::disconnectCallback ( const redisAsyncContext *c, int status )
{
	RegistrarDbRedisAsync *zis= ( RegistrarDbRedisAsync * ) c->data;
	zis->mContext=NULL;
	if ( status != REDIS_OK ) {
		LOGE ( "Redis disconnection message: %s", c->errstr );
		return;
	}
	LOGD ( "Disconnected %p...", c );
}

bool RegistrarDbRedisAsync::isConnected()
{
	return mContext != NULL;
}

static void handleAuthReply ( redisAsyncContext* ac, void *r, void *privdata )
{
	redisReply *reply = ( redisReply * ) r;
	if ( !reply || reply->type == REDIS_REPLY_ERROR ) {
		LOGE ( "Could'nt authenticate with redis server" );
		redisAsyncDisconnect ( ac );
	}
}


bool RegistrarDbRedisAsync::connect()
{
	if ( isConnected() ) {
		LOGW ( "Redis already connected" );
		return true;
	}

	mContext = redisAsyncConnect ( sDomain.c_str(), sPort );
	mContext->data=this;
	if ( mContext->err ) {
		LOGE ( "Redis Connection error: %s", mContext->errstr );
		redisAsyncFree ( mContext );
		mContext=NULL;
		return false;
	}

#ifndef WITHOUT_HIREDIS_CONNECT_CALLBACK
	redisAsyncSetConnectCallback ( mContext, connectCallback );
#endif

	redisAsyncSetDisconnectCallback ( mContext, disconnectCallback );

	if ( REDIS_OK != redisSofiaAttach ( mContext, mRoot ) ) {
		LOGE ( "Redis Connection error" );
		redisAsyncDisconnect ( mContext );
		mContext=NULL;
		return false;
	}

	if ( !sAuthPassword.empty() ) {
		redisAsyncCommand ( mContext, handleAuthReply, NULL, "AUTH %s", sAuthPassword.c_str() );
	}
	return true;
}

unsigned long RegistrarDbRedisAsync::getToken()
{
	if ( mToken == LONG_MAX ) {
		mToken=0;
	}
	return mToken++;
}


typedef void ( forwardFn ) ( redisAsyncContext*, redisReply*,RegistrarDbRedisAsync::RegistrarUserData * );

struct RegistrarDbRedisAsync::RegistrarUserData {
	RegistrarDbRedisAsync *self;
	char key[AOR_KEY_SIZE];
	forwardFn *fn;
	unsigned long token;
	const sip_contact_t * sipContact;
	const char * calldId;
	uint32_t csSeq;
	shared_ptr<RegistrarDbListener>listener;
	Record record;
	int globalExpire;
	const sip_path_t *path;
	bool alias;

	RegistrarUserData ( RegistrarDbRedisAsync *self, const url_t* url, const sip_contact_t *sip_contact, const char * calld_id, uint32_t cs_seq, const sip_path_t *path, bool alias, shared_ptr<RegistrarDbListener>listener, forwardFn *fn ) :
		self ( self ),fn ( fn ),token ( 0 ),sipContact ( sip_contact ),calldId ( calld_id ),csSeq ( cs_seq ),listener ( listener ),record ( "" ),globalExpire ( 0 ), path ( path ), alias ( alias ) {
		self->defineKeyFromUrl ( key,AOR_KEY_SIZE-1, url );
		record.setKey ( key );
	}
	RegistrarUserData ( RegistrarDbRedisAsync *self, const url_t* url, const sip_contact_t *sip_contact, const char * calld_id, uint32_t cs_seq, shared_ptr<RegistrarDbListener>listener, forwardFn *fn ) :
		self ( self ),fn ( fn ),token ( 0 ),sipContact ( sip_contact ),calldId ( calld_id ),csSeq ( cs_seq ),listener ( listener ),record ( "" ),globalExpire ( 0 ) {
		self->defineKeyFromUrl ( key,AOR_KEY_SIZE-1, url );
		record.setKey ( key );
	}
	RegistrarUserData ( RegistrarDbRedisAsync *self, const url_t *url, shared_ptr<RegistrarDbListener>listener, forwardFn *fn ) :
		self ( self ),fn ( fn ),token ( 0 ),sipContact ( NULL ),calldId ( NULL ),csSeq ( -1 ),listener ( listener ),record ( "" ),globalExpire ( 0 ) {
		self->defineKeyFromUrl ( key,AOR_KEY_SIZE-1, url );
		record.setKey ( key );
	}
	~RegistrarUserData() {
	}
};


/**
 * All three actions BIND, CLEAR and FETCH require first a retrieving of
 * the serialized contacts currently stored on the server.
 * If the redis reply is valid, the reply is forwarded to an action specific method.
 */
void RegistrarDbRedisAsync::sHandleAorGetReply ( redisAsyncContext* ac, void *r, void *privdata )
{
	redisReply *reply = ( redisReply * ) r;
	RegistrarUserData *data= ( RegistrarUserData * ) privdata;
	if ( !reply || reply->type == REDIS_REPLY_ERROR ) {
			LOGE ( "Redis error getting aor:%s [%lu] - %s", data->key, data->token, reply?reply->str:"null reply" );
			ERROR
		}

	LOGD ( "GOT aor:%s [%lu] --> %i bytes", data->key,data->token, reply->len );
	data->fn ( ac,reply,data );
}

void RegistrarDbRedisAsync::sHandleSet ( redisAsyncContext* ac, void *r, void *privdata )
{
	redisReply *reply = ( redisReply * ) r;
	RegistrarUserData *data= ( RegistrarUserData * ) privdata;
	if ( !reply || reply->type == REDIS_REPLY_ERROR ) {
			LOGE ( "Redis error setting aor:%s [%lu] - %s", data->key, data->token, reply?reply->str:"null reply" );
			ERROR
		}
	LOGD ( "Sent updated aor:%s [%lu] success", data->key,data->token );
	data->listener->onRecordFound ( &data->record );
	delete data;
}




void RegistrarDbRedisAsync::sHandleBind ( redisAsyncContext* ac, redisReply *reply, RegistrarUserData *data )
{
	data->self->handleBind ( reply,data );
}

void RegistrarDbRedisAsync::sHandleClear ( redisAsyncContext* ac, redisReply *reply, RegistrarUserData *data )
{
	data->self->handleClear ( reply,data );
}

void RegistrarDbRedisAsync::sHandleFetch ( redisAsyncContext* ac, redisReply *reply, RegistrarUserData *data )
{
	data->self->handleFetch ( reply,data );
}






void RegistrarDbRedisAsync::handleFetch ( redisReply *reply, RegistrarUserData *data )
{
	if ( reply->len>0 ) {
		if ( !mSerializer->parse ( reply->str, reply->len, &data->record ) ) {
			LOGE ( "Couldn't parse stored contacts for aor:%s : %u bytes", data->key, reply->len );
			ERROR
		}
		time_t now=getCurrentTime();
		data->record.clean ( now );
		data->listener->onRecordFound ( &data->record );
	}else {
		data->listener->onRecordFound ( NULL );
	}
	delete data;
}




void RegistrarDbRedisAsync::handleClear ( redisReply *reply, RegistrarUserData *data )
{
	if ( reply->str > 0 ) {
		if ( !mSerializer->parse ( reply->str, reply->len, &data->record ) ) {
			LOGE ( "Couldn't parse stored contacts for aor:%s : %i bytes", data->key, reply->len );
			ERROR
		}
		if ( data->record.isInvalidRegister ( data->calldId, data->csSeq ) ) {
			data->listener->onInvalid();
			delete data;
			return;
		}
	}
	chk_redis_err ( redisAsyncCommand ( mContext, sHandleSet, data,"DEL aor:%s",data->key ) );
}




void RegistrarDbRedisAsync::handleBind ( redisReply *reply, RegistrarUserData *data )
{
	if ( !mSerializer->parse ( reply->str, reply->len, &data->record ) ) {
		LOGE ( "Couldn't parse stored contacts for aor:%s : %u bytes", data->key, reply->len );
		ERROR
	}


	if ( data->record.isInvalidRegister ( data->calldId, data->csSeq ) ) {
		data->listener->onInvalid();
		delete data;
		return;
	}

	time_t now=getCurrentTime();
	data->record.clean ( data->sipContact, data->calldId, data->csSeq, now );
	data->record.update ( data->sipContact, data->path, data->globalExpire, data->calldId, data->csSeq, now, data->alias );
	mLocalRegExpire->update ( data->record );

	string serialized;
	mSerializer->serialize ( &data->record, serialized );
	LOGD ( "Sending updated aor:%s [%lu] --> %u bytes", data->key,data->token, ( unsigned ) serialized.length() );
	chk_redis_err ( redisAsyncCommand ( mContext, sHandleSet, data,"SET aor:%s %b",data->key, serialized.data(), serialized.length() ) );

	time_t expireat=data->record.latestExpire();
	chk_redis_err ( redisAsyncCommand ( data->self->mContext, NULL, NULL,"EXPIREAT aor:%s %lu",data->key, expireat ) );
}


void RegistrarDbRedisAsync::doBind ( const RegistrarDb::BindParameters& p, const shared_ptr< RegistrarDbListener >& listener )
{
	RegistrarUserData *data=new RegistrarUserData ( this,
		p.sip.from,p.sip.contact,p.sip.call_id,p.sip.cs_seq, p.sip.path, p.alias,listener,sHandleBind );
	data->globalExpire=p.global_expire;
	if ( !isConnected() && !connect() ) {
		LOGE ( "Not connected to redis server" );
		ERROR
	}
	if ( errorOnTooMuchContactInBind ( p.sip.contact,data->key,listener ) ) {
		ERROR
	}

	LOGD ( "Binding aor:%s [%lu]", data->key, data->token );
	chk_redis_err ( redisAsyncCommand ( mContext, sHandleAorGetReply,data,"GET aor:%s",data->key ) );
}

void RegistrarDbRedisAsync::doClear ( const sip_t *sip, const shared_ptr<RegistrarDbListener> &listener )
{
	RegistrarUserData *data=new RegistrarUserData ( this, sip->sip_from->a_url,sip->sip_contact, sip->sip_call_id->i_id, sip->sip_cseq->cs_seq, listener, sHandleClear );
	if ( !isConnected() && !connect() ) {
		LOGE ( "Not connected to redis server" );
		ERROR
	}
	LOGD ( "Clearing aor:%s [%lu]", data->key, data->token );
	mLocalRegExpire->remove ( data->key );
	chk_redis_err ( redisAsyncCommand ( mContext, sHandleAorGetReply,data,"GET aor:%s",data->key ) );
}




void RegistrarDbRedisAsync::doFetch ( const url_t *url, const shared_ptr<RegistrarDbListener> &listener )
{
	RegistrarUserData *data=new RegistrarUserData ( this,url,listener,sHandleFetch );
	if ( !isConnected() && !connect() ) {
		LOGE ( "Not connected to redis server" );
		ERROR
	}
	LOGD ( "Fetching aor:%s [%lu]", data->key, data->token );
	chk_redis_err ( redisAsyncCommand ( mContext, sHandleAorGetReply,data,"GET aor:%s",data->key ) );
}
