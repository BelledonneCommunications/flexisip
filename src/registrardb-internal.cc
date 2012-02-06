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

#include "registrardb.hh"
#include "registrardb-internal.hh"
#include "common.hh"

#include <ctime>
#include <cstdio>
#include <vector>
#include <algorithm>


#include <sofia-sip/sip_protos.h>

using namespace::std;

RegistrarDbInternal::RegistrarDbInternal() {
}

void RegistrarDbInternal::bind(const url_t* fromUrl, const sip_contact_t *sip_contact, const char * calld_id, uint32_t cs_seq, const char *route, int global_expire, RegistrarDbListener *listener) {
        char key[AOR_KEY_SIZE] = {0};
        defineKeyFromUrl(key, AOR_KEY_SIZE - 1, fromUrl);

        if (count_sip_contacts(sip_contact) > Record::getMaxContacts()) {
                LOGD("Too many contacts in register %s %i > %i",
                        key,
                        count_sip_contacts(sip_contact),
                        Record::getMaxContacts());

                listener->onError();
                return;
        }

        time_t now = time(NULL);

        map<string, Record*>::iterator it = mRecords.find(key);
        Record *r;
        if (it == mRecords.end()) {
                r = new Record();
                mRecords.insert(make_pair(key, r));
                LOGD("Creating AOR %s association", key);
        } else {
                LOGD("AOR %s found", key);
                r = (*it).second;
        }

        if (r->isInvalidRegister(calld_id, cs_seq)) {
                listener->onInvalid();
                return;
        }

        r->clean(sip_contact, calld_id, cs_seq, now);
        r->bind(sip_contact, route, global_expire, calld_id, cs_seq, now);
        listener->onRecordFound(r);
}

void RegistrarDbInternal::bind(const sip_t *sip, const char *route, int global_expire, RegistrarDbListener *listener) {
        bind(sip->sip_from->a_url, sip->sip_contact, sip->sip_call_id->i_id, sip->sip_cseq->cs_seq, route, global_expire, listener);
}

void RegistrarDbInternal::fetch(const url_t *url, RegistrarDbListener *listener) {
        char key[AOR_KEY_SIZE] = {0};
        defineKeyFromUrl(key, AOR_KEY_SIZE - 1, url);
        map<string, Record*>::iterator it = mRecords.find(key);
        Record *r = NULL;
        if (it != mRecords.end()) {
                r = (*it).second;
                r->clean(time(NULL));
        }

        listener->onRecordFound(r);
}

void RegistrarDbInternal::clear(const sip_t *sip, RegistrarDbListener *listener) {
        char key[AOR_KEY_SIZE] = {0};
        defineKeyFromUrl(key, AOR_KEY_SIZE - 1, sip->sip_from->a_url);

        if (errorOnTooMuchContactInBind(sip->sip_contact, key, listener)) {
                listener->onError();
                return;
        }

        map<string, Record*>::iterator it = mRecords.find(key);

        if (it == mRecords.end()) {
                listener->onRecordFound(NULL);
                return;
        }

        LOGD("AOR %s found", key);
        Record *r = (*it).second;

        if (r->isInvalidRegister(sip->sip_call_id->i_id, sip->sip_cseq->cs_seq)) {
                listener->onInvalid();
                return;
        }

        mRecords.erase(it);
        listener->onRecordFound(NULL);
}
