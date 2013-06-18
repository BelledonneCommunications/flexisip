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

#ifndef registrardb_redis_hh
#define registrardb_redis_hh

#include "registrardb.hh"
#include "recordserializer.hh"
#include <sofia-sip/sip.h>
#include <sofia-sip/nta.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include "agent.hh"

class RegistrarDbRedisSync : public RegistrarDb {
        RegistrarDbRedisSync(Agent *ag);
        ~RegistrarDbRedisSync();
        bool isConnected();
        friend class RegistrarDb;
        redisContext *mContext;
        RecordSerializer *mSerializer;
        static std::string sDomain;
        static std::string sAuthPassword;
        static int sPort;
        static int sTimeout;
protected:
        bool connect();
        virtual void doBind(const url_t* url, const sip_contact_t* sip_contact, const char* calld_id, uint32_t cs_seq, const sip_path_t* path, const char* route, int global_expire, bool alias, const std::shared_ptr< RegistrarDbListener >& listener);
        virtual void doClear(const sip_t *sip, const std::shared_ptr<RegistrarDbListener> &listener);
        virtual void doFetch(const url_t *url, const std::shared_ptr<RegistrarDbListener> &listener);
};

class RegistrarDbRedisAsync : public RegistrarDb {
public:
        struct RegistrarUserData;

protected:
        bool connect();
	virtual void doBind(const url_t* fromUrl, const sip_contact_t *sip_contact, const char * calld_id, uint32_t cs_seq, const sip_path_t *path, const char *route, int global_expire, bool alias, const std::shared_ptr<RegistrarDbListener> &listener);
        virtual void doClear(const sip_t *sip, const std::shared_ptr<RegistrarDbListener> &listener);
        virtual void doFetch(const url_t *url, const std::shared_ptr<RegistrarDbListener> &listener);

private:
        RegistrarDbRedisAsync(Agent *ag);
        ~RegistrarDbRedisAsync();
        static void connectCallback(const redisAsyncContext *c, int status);
        static void disconnectCallback(const redisAsyncContext *c, int status);
        bool isConnected();
        friend class RegistrarDb;
        redisAsyncContext *mContext;
        RecordSerializer *mSerializer;
        static std::string sDomain;
        static std::string sAuthPassword;
        static int sPort;
        static int sTimeout;
        su_root_t *mRoot;
        unsigned long mToken;
        unsigned long getToken();
        static void sHandleSet(redisAsyncContext* ac, void *r, void *privdata);
        static void sHandleAorGetReply(struct redisAsyncContext*, void *r, void *privdata);
        static void sHandleBind(redisAsyncContext* ac, redisReply *reply, RegistrarUserData *data);
        static void sHandleFetch(redisAsyncContext* ac, redisReply *reply, RegistrarUserData *data);
        static void sHandleClear(redisAsyncContext* ac, redisReply *reply, RegistrarUserData *data);
        void handleClear(redisReply *reply, RegistrarUserData *data);
        void handleFetch(redisReply *reply, RegistrarUserData *data);
        void handleBind(redisReply *reply, RegistrarUserData *data);
        void onBindReplyAorSet(redisReply *reply, RegistrarUserData *data);

};


#endif
