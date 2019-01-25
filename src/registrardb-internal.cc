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

#include <flexisip/registrardb.hh>
#include "registrardb-internal.hh"
#include <flexisip/common.hh>

#include <ctime>
#include <cstdio>
#include <vector>
#include <algorithm>

#include <sofia-sip/sip_protos.h>

using namespace std;
using namespace flexisip;

RegistrarDbInternal::RegistrarDbInternal(Agent *ag) : RegistrarDb(ag) {
	mWritable = true;
}

void RegistrarDbInternal::doBind(const sip_t *sip, int globalExpire, bool alias, int version, const shared_ptr<ContactUpdateListener> &listener) {
	string key = Record::defineKeyFromUrl(sip->sip_from->a_url);

	auto it = mRecords.find(key);
	shared_ptr<Record> r;
	if (sip->sip_from && it == mRecords.end()) {
		r = make_shared<Record>(sip->sip_from->a_url);
		mRecords.insert(make_pair(key, r));
		LOGD("Creating AOR %s association", key.c_str());
	} else {
		LOGD("AOR %s found", key.c_str());
		r = (*it).second;
	}

	if (sip->sip_call_id && sip->sip_cseq && r->isInvalidRegister(sip->sip_call_id->i_id, sip->sip_cseq->cs_seq)) {
		LOGD("Invalid register");
		if (listener) listener->onInvalid();
		return;
	}

	r->update(sip, globalExpire, alias, version, listener);

	mLocalRegExpire->update(r);
	if (listener) listener->onRecordFound(r);
}

void RegistrarDbInternal::doFetch(const url_t *url, const shared_ptr<ContactUpdateListener> &listener) {
	string key(Record::defineKeyFromUrl(url));

	auto it = mRecords.find(key);
	shared_ptr<Record> r = NULL;
	if (it != mRecords.end()) {
		r = (*it).second;
		r->clean(getCurrentTime(), listener);
		if (r->isEmpty()) {
			mRecords.erase(it);
			r = nullptr;
		}
	}

	listener->onRecordFound(r);
}

void RegistrarDbInternal::doFetchForGruu(const url_t *url, const string &gruu, const shared_ptr<ContactUpdateListener> &listener) {
	string key(Record::defineKeyFromUrl(url));
	SofiaAutoHome home;

	auto it = mRecords.find(key);
	shared_ptr<Record> r = NULL;

	if (it == mRecords.end()) {
		listener->onRecordFound(r);
		return;
	}

	r = (*it).second;
	r->clean(getCurrentTime(), listener);
	if (r->isEmpty()) {
		mRecords.erase(it);
		r = nullptr;
		listener->onRecordFound(r);
		return;
	}

	const list<shared_ptr<ExtendedContact>> &contacts = r->getExtendedContacts();
	shared_ptr<Record> retRecord = make_shared<Record>(url);
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

		retRecord->pushContact(contact);
	}

	listener->onRecordFound(retRecord);
}

void RegistrarDbInternal::doClear(const sip_t *sip, const shared_ptr<ContactUpdateListener> &listener) {
	string key(Record::defineKeyFromUrl(sip->sip_from->a_url));

	if (errorOnTooMuchContactInBind(sip->sip_contact, key, listener)) {
		listener->onError();
		return;
	}

	auto it = mRecords.find(key);

	if (it == mRecords.end()) {
		listener->onRecordFound(NULL);
		return;
	}

	LOGD("AOR %s found", key.c_str());
	shared_ptr<Record> r = (*it).second;

	if (r->isInvalidRegister(sip->sip_call_id->i_id, sip->sip_cseq->cs_seq)) {
		listener->onInvalid();
		return;
	}

	mRecords.erase(it);
	mLocalRegExpire->remove(key);
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
