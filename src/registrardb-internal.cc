/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "registrardb-internal.hh"

#include <cstdio>
#include <ctime>
#include <vector>

#include "flexisip/registrar/registar-listeners.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"

#include "registrar/change-set.hh"
#include "registrar/exceptions.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"

using namespace std;
using namespace flexisip;

RegistrarDbInternal::RegistrarDbInternal(const Record::Config& recordConfig,
                                         LocalRegExpire& localRegExpire,
                                         std::function<void(const Record::Key&, const std::string&)> notify)
    : mRecordConfig{recordConfig}, mLocalRegExpire{localRegExpire}, mNotifyContactListener{std::move(notify)} {
}

void RegistrarDbInternal::doBind(const MsgSip& msg,
                                 const BindingParameters& parameters,
                                 const shared_ptr<ContactUpdateListener>& listener) {
	auto sip = msg.getSip();
	SipUri fromUri;
	try {
		fromUri = SipUri(sip->sip_from->a_url);
	} catch (const sofiasip::InvalidUrlError& e) {
		THROW_LINE(InvalidAorError, sip->sip_from->a_url);
	}

	const auto& key = Record::Key(fromUri, mRecordConfig.useGlobalDomain()).toString();

	auto it = mRecords.find(key);
	shared_ptr<Record> r{};
	if (it == mRecords.end()) {
		r = make_shared<Record>(std::move(fromUri), mRecordConfig);
		it = mRecords.insert(make_pair(key, r)).first;
		LOGD("Creating Asip_contact_tOR %s association", key.c_str());
	} else {
		LOGD("AOR %s found", key.c_str());
		r = it->second;
	}

	try {
		r->update(sip, parameters, listener);
	} catch (const InvalidRequestError& e) {
		if (listener) listener->onInvalid(e.getSipStatus());
		return;
	}

	mLocalRegExpire.update(r);
	if (r->isEmpty()) mRecords.erase(it);
	if (listener) listener->onRecordFound(r);
}

void RegistrarDbInternal::doFetch(const SipUri& url, const shared_ptr<ContactUpdateListener>& listener) {
	auto it = mRecords.find(Record::Key(url, mRecordConfig.useGlobalDomain()).toString());
	shared_ptr<Record> r{};
	if (it != mRecords.end()) {
		r = (*it).second;
		r->clean(listener);
		if (r->isEmpty()) {
			mRecords.erase(it);
			r = nullptr;
		}
	}

	listener->onRecordFound(r);
}

void RegistrarDbInternal::doFetchInstance(const SipUri& url,
                                          const string& uniqueId,
                                          const shared_ptr<ContactUpdateListener>& listener) {
	sofiasip::Home home;

	auto it = mRecords.find(Record::Key(url, mRecordConfig.useGlobalDomain()).toString());
	shared_ptr<Record> r{};

	if (it == mRecords.end()) {
		listener->onRecordFound(r);
		return;
	}

	r = (*it).second;
	r->clean(listener);
	if (r->isEmpty()) {
		mRecords.erase(it);
		r = nullptr;
		listener->onRecordFound(r);
		return;
	}

	const auto& contacts = r->getExtendedContacts();
	shared_ptr<Record> retRecord = make_shared<Record>(url, mRecordConfig);
	auto& retContacts = retRecord->getExtendedContacts();
	for (const auto& contact : contacts) {
		if (contact->mKey == uniqueId) {
			retContacts.emplace(contact);
			break;
		}
	}
	listener->onRecordFound(retRecord);
}

void RegistrarDbInternal::fetchExpiringContacts(time_t current_time,
                                                float threshold,
                                                std::function<void(std::vector<ExtendedContact>&&)>&& callback) const {
	auto expiringContacts = std::vector<ExtendedContact>();
	for (const auto& pair : mRecords) {
		for (const auto& contact : pair.second->getExtendedContacts()) {
			const auto& url = contact->mSipContact->m_url;
			if (!url_has_param(url, "pn-provider") && !url_has_param(url, "pn-type")) continue;

			const auto expires = contact->getSipExpires().count();
			const auto threshold_time = contact->getRegisterTime() + long(threshold * expires);
			if (threshold_time < current_time && current_time < contact->getSipExpireTime()) {
				expiringContacts.emplace_back(*contact);
			}
		}
	}
	callback(std::move(expiringContacts));
}

void RegistrarDbInternal::doClear(const MsgSip& msg, const shared_ptr<ContactUpdateListener>& listener) {
	auto* sip = msg.getSip();
	const auto& key = Record::Key(sip->sip_from->a_url, mRecordConfig.useGlobalDomain()).toString();

	if (errorOnTooMuchContactInBind(sip->sip_contact, key)) {
		listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
		return;
	}

	auto it = mRecords.find(key);

	if (it == mRecords.end()) {
		listener->onRecordFound(nullptr);
		return;
	}

	LOGD("AOR %s found", key.c_str());
	shared_ptr<Record> r = (*it).second;

	mRecords.erase(it);
	mLocalRegExpire.remove(key);
	listener->onRecordFound(nullptr);
}

void RegistrarDbInternal::clearAll() {
	mRecords.clear();
	mLocalRegExpire.clearAll();
}

void RegistrarDbInternal::publish(const Record::Key& topic, const string& uid) {
	mNotifyContactListener(topic, uid);
}

bool RegistrarDbInternal::errorOnTooMuchContactInBind(const sip_contact_t* sip_contact, const string& key) {
	int nb_contact = RegistrarDb::countSipContacts(sip_contact);
	int max_contact = mRecordConfig.getMaxContacts();
	if (nb_contact > max_contact) {
		LOGD("Too many contacts in register %s %i > %i", key.c_str(), nb_contact, max_contact);
		return true;
	}

	return false;
}
