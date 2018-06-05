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

#include "registrardb.hh"
#include "registrardb-internal.hh"
#include "common.hh"

#include <ctime>
#include <cstdio>
#include <vector>
#include <algorithm>

#include <sofia-sip/sip_protos.h>

using namespace std;

RegistrarDbInternal::RegistrarDbInternal(Agent *ag) : RegistrarDb(ag) {
}

void RegistrarDbInternal::doBind(const url_t *ifrom, sip_contact_t *icontact, const char *iid, uint32_t iseq,
						const sip_path_t *ipath, list<string> acceptHeaders, bool usedAsRoute, int expire, int alias, int version,
						const shared_ptr<ContactUpdateListener> &listener) {
	string key = Record::defineKeyFromUrl(ifrom);
	time_t now = getCurrentTime();

	map<string, Record *>::iterator it = mRecords.find(key);
	Record *r;
	if (it == mRecords.end()) {
		r = new Record(ifrom);
		mRecords.insert(make_pair(key, r));
		LOGD("Creating AOR %s association", key.c_str());
	} else {
		LOGD("AOR %s found", key.c_str());
		r = (*it).second;
	}

	if (r->isInvalidRegister(iid, iseq)) {
		LOGD("Invalid register");
		listener->onInvalid();
		return;
	}

	r->update(icontact, ipath, expire, iid, iseq, now, alias, acceptHeaders, usedAsRoute, listener);

	mLocalRegExpire->update(*r);
	listener->onRecordFound(r);
}

void RegistrarDbInternal::doFetch(const url_t *url, const shared_ptr<ContactUpdateListener> &listener) {
	string key(Record::defineKeyFromUrl(url));

	map<string, Record *>::iterator it = mRecords.find(key);
	Record *r = NULL;
	if (it != mRecords.end()) {
		r = (*it).second;
		r->clean(getCurrentTime(), listener);
		if (r->isEmpty()) {
			mRecords.erase(it);
			delete r;
			r = NULL;
		}
	}

	listener->onRecordFound(r);
}

void RegistrarDbInternal::doFetchForGruu(const url_t *url, const string &gruu, const shared_ptr<ContactUpdateListener> &listener) {
	string key(Record::defineKeyFromUrl(url));
	SofiaAutoHome home;

	map<string, Record *>::iterator it = mRecords.find(key);
	Record *r = NULL;

	if (it == mRecords.end()) {
		listener->onRecordFound(r);
		return;
	}

	r = (*it).second;
	r->clean(getCurrentTime(), listener);
	if (r->isEmpty()) {
		mRecords.erase(it);
		delete r;
		r = NULL;
		listener->onRecordFound(r);
		return;
	}

	const list<shared_ptr<ExtendedContact>> &contacts = r->getExtendedContacts();
	Record retRecord(url);
	for (const auto &contact : contacts) {
		if (!url_has_param(contact->mSipContact->m_url, "gr"))
			continue;

		char buffer[255] = {0};
		isize_t result = url_param(contact->mSipContact->m_url->url_params, "gr", buffer, sizeof(buffer) - 1);
		if (result <= 0)
			continue;

		stringstream streamGruu;
		streamGruu << "\"<" << buffer << ">\"";
		if (streamGruu.str() != gruu)
			continue;

		retRecord.pushContact(contact);
	}

	listener->onRecordFound(&retRecord);
}

void RegistrarDbInternal::doClear(const sip_t *sip, const shared_ptr<ContactUpdateListener> &listener) {
	string key(Record::defineKeyFromUrl(sip->sip_from->a_url));

	if (errorOnTooMuchContactInBind(sip->sip_contact, key, listener)) {
		listener->onError();
		return;
	}

	map<string, Record *>::iterator it = mRecords.find(key);

	if (it == mRecords.end()) {
		listener->onRecordFound(NULL);
		return;
	}

	LOGD("AOR %s found", key.c_str());
	Record *r = (*it).second;

	if (r->isInvalidRegister(sip->sip_call_id->i_id, sip->sip_cseq->cs_seq)) {
		listener->onInvalid();
		return;
	}

	mRecords.erase(it);
	mLocalRegExpire->remove(key);
	delete r;
	listener->onRecordFound(NULL);
}

void RegistrarDbInternal::doMigration() {

}

void RegistrarDbInternal::clearAll() {
	mRecords.clear();
	mLocalRegExpire->clearAll();
}

void RegistrarDbInternal::publish(const string &topic, const string &uid) {
	LOGD("Publish topic = %s, uid = %s", topic.c_str(), uid.c_str());
	RegistrarDb::notifyContactListener(topic, uid);
}
