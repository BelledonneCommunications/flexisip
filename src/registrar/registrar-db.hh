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

#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "registrar/record.hh"
#include "sofia-sip/sip.h"
#include "utils/cast-to-const.hh"

namespace sofiasip {
class MsgSip;
}

namespace flexisip {

class Agent;
class ContactRegisteredListener;
class ContactUpdateListener;
class ListContactUpdateListener;
class LocalRegExpireListener;
class Record;
class RegistrarDbListener;
class RegistrarDbStateListener;
class SipUri;
struct BindingParameters;
struct ExtendedContact;

class RegistrarDbBackend {
public:
	virtual ~RegistrarDbBackend() = default;
	virtual void fetchExpiringContacts(time_t startTimestamp,
	                                   float threshold,
	                                   std::function<void(std::vector<ExtendedContact>&&)>&& callback) const = 0;
	virtual bool isWritable() const = 0;
	virtual void doBind(const sofiasip::MsgSip& sip,
	                    const BindingParameters& parameters,
	                    const std::shared_ptr<ContactUpdateListener>& listener) = 0;
	virtual void doClear(const sofiasip::MsgSip& sip, const std::shared_ptr<ContactUpdateListener>& listener) = 0;
	virtual void doFetch(const SipUri& url, const std::shared_ptr<ContactUpdateListener>& listener) = 0;
	virtual void doFetchInstance(const SipUri& url,
	                             const std::string& uniqueId,
	                             const std::shared_ptr<ContactUpdateListener>& listener) = 0;
	virtual void subscribe(const Record::Key&) = 0;
	virtual void unsubscribe(const Record::Key&) = 0;
	virtual void publish(const Record::Key& topic, const std::string& uid) = 0;
};
class LocalRegExpire {
public:
	LocalRegExpire() = default;
	void remove(const std::string& key) {
		std::lock_guard<std::mutex> lock(mMutex);
		mRegMap.erase(key);
	}
	void update(const std::shared_ptr<Record>& record);
	size_t countActives();
	void removeExpiredBefore(time_t before);
	void clearAll() {
		std::lock_guard<std::mutex> lock(mMutex);
		mRegMap.clear();
	}
	void getRegisteredAors(std::list<std::string>& aors) const;

	void subscribe(LocalRegExpireListener* listener);
	void unsubscribe(LocalRegExpireListener* listener);
	void notifyLocalRegExpireListener(unsigned int count);
	void setLatestExpirePredicate(std::function<bool(const url_t*)> predicate) {
		mLatestExpirePredicate = std::move(predicate);
	}

private:
	std::map<std::string, time_t> mRegMap;
	mutable std::mutex mMutex;
	std::list<LocalRegExpireListener*> mLocalRegListenerList;
	std::function<bool(const url_t* url)> mLatestExpirePredicate{[](const url_t*) { return false; }};
};

/**
 * A class which holds records contact addresses associated with a from.
 * Both local and remote storage implementations exist.
 * It is used by the Registrar module.
 **/
class RegistrarDb {
	friend class ModuleRegistrar;

public:
	RegistrarDb(const std::shared_ptr<sofiasip::SuRoot>& root, const std::shared_ptr<ConfigManager>& cfg);
	virtual ~RegistrarDb() = default;

	void bind(sofiasip::MsgSip&& sipMsg,
	          const BindingParameters& parameter,
	          const std::shared_ptr<ContactUpdateListener>& listener);
	void bind(const sofiasip::MsgSip& sipMsg,
	          const BindingParameters& parameter,
	          const std::shared_ptr<ContactUpdateListener>& listener);
	void bind(const SipUri& from,
	          const sip_contact_t* contact,
	          const BindingParameters& parameter,
	          const std::shared_ptr<ContactUpdateListener>& listener);
	void clear(const sofiasip::MsgSip& sip, const std::shared_ptr<ContactUpdateListener>& listener);
	void clear(const SipUri& url, const std::string& callId, const std::shared_ptr<ContactUpdateListener>& listener);
	void fetch(const SipUri& url, const std::shared_ptr<ContactUpdateListener>& listener, bool recursive = false);
	void fetch(const SipUri& url,
	           const std::shared_ptr<ContactUpdateListener>& listener,
	           bool includingDomains,
	           bool recursive);
	void fetchList(const std::vector<SipUri> urls, const std::shared_ptr<ListContactUpdateListener>& listener);
	void fetchExpiringContacts(time_t startTimestamp,
	                           float threshold,
	                           std::function<void(std::vector<ExtendedContact>&&)>&& callback) const {
		mBackend->fetchExpiringContacts(startTimestamp, threshold, std::move(callback));
	}
	void notifyContactListener(const std::shared_ptr<Record>& r /*might be empty record*/, const std::string& uid);
	void updateRemoteExpireTime(const std::string& key, time_t expireat);
	unsigned long countLocalActiveRecords() {
		return mLocalRegExpire.countActives();
	}

	void addStateListener(const std::shared_ptr<RegistrarDbStateListener>& listener);
	void removeStateListener(const std::shared_ptr<RegistrarDbStateListener>& listener);
	bool isWritable() const {
		return mBackend->isWritable();
	}
	/* Returns true if bindings can create a pub-gruu address (when supported by the registering client)*/
	bool gruuEnabled() const {
		return mGruuEnabled;
	};

	/**
	 * @return true if a subscribe was necessary (not already subscribed topic)
	 */
	bool subscribe(const Record::Key& topic, std::weak_ptr<ContactRegisteredListener>&& listener);
	void unsubscribe(const Record::Key& topic, const std::shared_ptr<ContactRegisteredListener>& listener);
	void publish(const Record::Key& topic, const std::string& uid);
	bool useGlobalDomain() const {
		return mRecordConfig.useGlobalDomain();
	}
	const Record::Config& getRecordConfig() const {
		return mRecordConfig;
	}

	void subscribeLocalRegExpire(LocalRegExpireListener* listener) {
		mLocalRegExpire.subscribe(listener);
	}
	void unsubscribeLocalRegExpire(LocalRegExpireListener* listener) {
		mLocalRegExpire.unsubscribe(listener);
	}
	/* Synthesize the pub-gruu SIP URI corresponding to a REGISTER message. +sip.instance is expected in the Contact
	 * header.*/
	url_t* synthesizePubGruu(su_home_t* home, const sofiasip::MsgSip& sipMsg);

	void getLocalRegisteredAors(std::list<std::string>& aors) const {
		mLocalRegExpire.getRegisteredAors(aors);
	}

	const std::multimap<std::string, std::weak_ptr<const ContactRegisteredListener>>&
	getOnContactRegisteredListeners() const {
		return castToConst(mContactListenersMap);
	}
	void setLatestExpirePredicate(std::function<bool(const url_t*)> predicate) {
		mLocalRegExpire.setLatestExpirePredicate(std::move(predicate));
	}
	static int countSipContacts(const sip_contact_t* contact);

	const RegistrarDbBackend& getRegistrarBackend() const {
		return *mBackend;
	}

private:
	void fetchWithDomain(const SipUri& url, const std::shared_ptr<ContactUpdateListener>& listener, bool recursive);
	void notifyContactListener(const Record::Key& key, const std::string& uid);
	void notifyStateListener(bool bWritable) const;

	std::shared_ptr<sofiasip::SuRoot> mRoot;
	std::shared_ptr<ConfigManager> mConfigManager;
	LocalRegExpire mLocalRegExpire{};
	bool mGruuEnabled{};
	Record::Config mRecordConfig;
	std::multimap<std::string, std::weak_ptr<ContactRegisteredListener>> mContactListenersMap;
	std::list<std::shared_ptr<RegistrarDbStateListener>> mStateListeners;
	// Must be last
	std::unique_ptr<RegistrarDbBackend> mBackend;
};

} // namespace flexisip
