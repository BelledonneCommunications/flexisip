/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <vector>

#include <sofia-sip/sip_protos.h>

#include <flexisip/common.hh>

#include "registrardb-internal.hh"
#include "registrardb.hh"

using namespace std;
using namespace flexisip;

RegistrarDbInternal::RegistrarDbInternal(Agent* ag) : RegistrarDb(ag) {
	mWritable = true;
}

void RegistrarDbInternal::doBind(const MsgSip& msg,
                                 const BindingParameters& parameters,
                                 const shared_ptr<ContactUpdateListener>& listener) {
	auto sip = msg.getSip();
	SipUri fromUri;
	try {
		fromUri = SipUri(sip->sip_from->a_url);
	} catch (const invalid_argument &e) {
		throw InvalidAorError(sip->sip_from->a_url);
	}

	string key = Record::defineKeyFromUrl(fromUri.get());

	auto it = mRecords.find(key);
	shared_ptr<Record> r;
	if (it == mRecords.end()) {
		r = make_shared<Record>(move(fromUri));
		mRecords.insert(make_pair(key, r));
		LOGD("Creating AOR %s association", key.c_str());
	} else {
		LOGD("AOR %s found", key.c_str());
		r = it->second;
	}

	if (sip->sip_call_id && sip->sip_cseq && r->isInvalidRegister(sip->sip_call_id->i_id, sip->sip_cseq->cs_seq)) {
		LOGD("Invalid register");
		if (listener) listener->onInvalid();
		return;
	}

	r->update(sip, parameters, listener);

	mLocalRegExpire->update(r);
	if (listener) listener->onRecordFound(r);
}

void RegistrarDbInternal::doFetch(const SipUri &url, const shared_ptr<ContactUpdateListener> &listener) {
	string key = Record::defineKeyFromUrl(url.get());

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

void RegistrarDbInternal::doFetchInstance(const SipUri &url, const string &uniqueId, const shared_ptr<ContactUpdateListener> &listener) {
	string key(Record::defineKeyFromUrl(url.get()));
	sofiasip::Home home;

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
		if (contact->mUniqueId == uniqueId){
			retRecord->pushContact(contact);
			break;
		}
	}
	listener->onRecordFound(retRecord);
}

void RegistrarDbInternal::fetchExpiringContacts(time_t startTimestamp,
                                                std::chrono::seconds timeRange,
                                                std::function<void(std::vector<ExtendedContact>&&)>&& callback) const {
	const auto deadline = startTimestamp + timeRange.count();
	auto expiringContacts = std::vector<ExtendedContact>();
	for (const auto& pair : mRecords) {
		for (const auto& contact : pair.second->getExtendedContacts()) {
			const auto expirationTime = contact->mExpireAt;
			if (startTimestamp <= expirationTime && expirationTime < deadline) {
				expiringContacts.emplace_back(*contact);
			}
		}
	}
	callback(std::move(expiringContacts));
}

void RegistrarDbInternal::doClear(const MsgSip &msg, const shared_ptr<ContactUpdateListener> &listener) {
	auto sip = msg.getSip();
	string key = Record::defineKeyFromUrl(sip->sip_from->a_url);

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
