/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2012  Belledonne Communications SARL.
    Author Guillaume Beraudo. Based on BSD libevent.h example from hiredis.

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

#ifndef sofia_redis_event_h
#define sofia_redis_event_h

#include "common.hh"
#include <hiredis/hiredis.h>
#include <hiredis/async.h>


struct redisSofiaEvents;
typedef struct redisSofiaEvents redisSofiaEvents;

#ifndef SU_WAIT_H
#define SU_WAKEUP_ARG_T redisSofiaEvents
#define SU_ROOT_MAGIC_T redisAsyncContext
#include <sofia-sip/su_wait.h>
#endif

typedef struct redisSofiaEvents {
    redisAsyncContext *context;
    su_root_t *root;
    su_wait_t wait;
    int index;
} redisSofiaEvents;

static int redisSofiaEvent(su_root_magic_t *magic, su_wait_t *wait, su_wakeup_arg_t *e) {
    //redisSofiaEvents *e = (redisSofiaEvents*)arg;
    if (wait->revents & SU_WAIT_IN){
    	redisAsyncHandleRead(((redisSofiaEvents*)e)->context);
    } if (wait->revents & SU_WAIT_OUT) {
        redisAsyncHandleWrite(((redisSofiaEvents*)e)->context);
    } else {
    	return 0; // ???
    }
    return 0; // ???
}


static void addWaitMask(void *privdata, int mask) {
    redisSofiaEvents *e = (redisSofiaEvents*)privdata;
	redisContext *c = &(e->context->c);
	int events=su_wait_events(&e->wait, c->fd);
	events |= mask;
	su_root_eventmask(e->root, e->index, c->fd, events);
}
static void delWaitMask(void *privdata, int mask) {
    redisSofiaEvents *e = (redisSofiaEvents*)privdata;
	redisContext *c = &(e->context->c);
	int events=su_wait_events(&e->wait, c->fd);
	events &= ~mask;
	su_root_eventmask(e->root, e->index, c->fd, events);
}

static void redisSofiaAddRead(void *privdata) {
	addWaitMask(privdata, SU_WAIT_IN);
}

static void redisSofiaDelRead(void *privdata) {
	delWaitMask(privdata, SU_WAIT_IN);
}

static void redisSofiaAddWrite(void *privdata) {
	addWaitMask(privdata, SU_WAIT_OUT);
}

static void redisSofiaDelWrite(void *privdata) {
	delWaitMask(privdata, SU_WAIT_OUT);

}

// Note: async.h requires this method to be idempotent; it is not the case.
static void redisSofiaCleanup(void *privdata) {
    redisSofiaEvents *e = (redisSofiaEvents*)privdata;
    su_root_deregister(e->root, e->index);
    LOGI("Redis sofia event cleaned %p", e->context);
    free(e);
}

static int redisSofiaAttach(redisAsyncContext *ac, su_root_t *root) {
    redisContext *c = &(ac->c);
    redisSofiaEvents *e;

    /* Nothing should be attached when something is already attached */
    if (ac->ev.data != NULL)
        return REDIS_ERR;

    /* Create container for context and r/w events */
    e = (redisSofiaEvents*)malloc(sizeof(*e));
    e->context = ac;
    e->root = root;

    /* Register functions to start/stop listening for events */
    ac->ev.addRead = redisSofiaAddRead;
    ac->ev.delRead = redisSofiaDelRead;
    ac->ev.addWrite = redisSofiaAddWrite;
    ac->ev.delWrite = redisSofiaDelWrite;
    ac->ev.cleanup = redisSofiaCleanup;
    ac->ev.data = e;

    /* Initialize and install read/write events */
    if (0!=su_wait_create(&e->wait, c->fd,SU_WAIT_IN|SU_WAIT_OUT)){
    	return REDIS_ERR;
    }
    e->index=su_root_register(root, &e->wait, redisSofiaEvent, e, su_pri_normal);

    return REDIS_OK;
}
#endif
