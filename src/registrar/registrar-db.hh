/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
#include <string>

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

/**
 * A singleton class which holds records contact addresses associated with a from.
 * Both local and remote storage implementations exist.
 * It is used by the Registrar module.
 **/
class RegistrarDb {
	friend class ModuleRegistrar;

public:
	virtual ~RegistrarDb();
	/**
	 * Reset RegistrarDb::sUnique
	 * WARNING : this method is ONLY there for testing purpose
	 */
	static void resetDB();
	static RegistrarDb* initialize(Agent* ag);
	/**
	 * Errors if the DB has not been initialized yet. Make sure to call Agent::loadConfig() before calling
	 * RegistrarDb::get()
	 */
	static RegistrarDb* get();
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
	virtual void fetchExpiringContacts(time_t startTimestamp,
	                                   float threshold,
	                                   std::function<void(std::vector<ExtendedContact>&&)>&& callback) const = 0;
	void notifyContactListener(const std::shared_ptr<Record>& r /*might be empty record*/, const std::string& uid);
	void updateRemoteExpireTime(const std::string& key, time_t expireat);
	unsigned long countLocalActiveRecords() {
		return mLocalRegExpire->countActives();
	}

	void addStateListener(const std::shared_ptr<RegistrarDbStateListener>& listener);
	void removeStateListener(const std::shared_ptr<RegistrarDbStateListener>& listener);
	bool isWritable() const {
		return mWritable;
	}
	/* Returns true if bindings can create a pub-gruu address (when supported by the registering client)*/
	bool gruuEnabled() const {
		return mGruuEnabled;
	};

	/**
	 * @return true if a subscribe was necessary (not already subscribed topic)
	 */
	virtual bool subscribe(const Record::Key& topic, std::weak_ptr<ContactRegisteredListener>&& listener);
	virtual void unsubscribe(const Record::Key& topic, const std::shared_ptr<ContactRegisteredListener>& listener);
	virtual void publish(const Record::Key& topic, const std::string& uid) = 0;
	bool useGlobalDomain() const {
		return mUseGlobalDomain;
	}
	const std::string& messageExpiresName() {
		return mMessageExpiresName;
	}
	const std::string getMessageExpires(const msg_param_t* m_params);

	void subscribeLocalRegExpire(LocalRegExpireListener* listener) {
		mLocalRegExpire->subscribe(listener);
	}
	void unsubscribeLocalRegExpire(LocalRegExpireListener* listener) {
		mLocalRegExpire->unsubscribe(listener);
	}
	/* Synthesize the pub-gruu SIP URI corresponding to a REGISTER message. +sip.instance is expected in the Contact
	 * header.*/
	url_t* synthesizePubGruu(su_home_t* home, const sofiasip::MsgSip& sipMsg);

	void getLocalRegisteredAors(std::list<std::string>& aors) const {
		mLocalRegExpire->getRegisteredAors(aors);
	}

	const std::multimap<const std::string, const std::weak_ptr<const ContactRegisteredListener>>&
	getOnContactRegisteredListeners() const {
		return castToConst(mContactListenersMap);
	}

protected:
	class LocalRegExpire {
		std::map<std::string, time_t> mRegMap;
		mutable std::mutex mMutex;
		std::list<LocalRegExpireListener*> mLocalRegListenerList;
		Agent* mAgent;

	public:
		void remove(const std::string& key) {
			std::lock_guard<std::mutex> lock(mMutex);
			mRegMap.erase(key);
		}
		void update(const std::shared_ptr<Record>& record);
		size_t countActives();
		void removeExpiredBefore(time_t before);
		LocalRegExpire(Agent* ag);
		void clearAll() {
			std::lock_guard<std::mutex> lock(mMutex);
			mRegMap.clear();
		}
		void getRegisteredAors(std::list<std::string>& aors) const;

		void subscribe(LocalRegExpireListener* listener);
		void unsubscribe(LocalRegExpireListener* listener);
		void notifyLocalRegExpireListener(unsigned int count);
	};

	RegistrarDb(Agent* ag);

	virtual void doBind(const sofiasip::MsgSip& sip,
	                    const BindingParameters& parameters,
	                    const std::shared_ptr<ContactUpdateListener>& listener) = 0;
	virtual void doClear(const sofiasip::MsgSip& sip, const std::shared_ptr<ContactUpdateListener>& listener) = 0;
	virtual void doFetch(const SipUri& url, const std::shared_ptr<ContactUpdateListener>& listener) = 0;
	virtual void doFetchInstance(const SipUri& url,
	                             const std::string& uniqueId,
	                             const std::shared_ptr<ContactUpdateListener>& listener) = 0;
	virtual void doMigration() = 0;

	int countSipContacts(const sip_contact_t* contact);
	bool errorOnTooMuchContactInBind(const sip_contact_t* sip_contact,
	                                 const std::string& key,
	                                 const std::shared_ptr<RegistrarDbListener>& listener);
	void fetchWithDomain(const SipUri& url, const std::shared_ptr<ContactUpdateListener>& listener, bool recursive);
	void notifyContactListener(const Record::Key& key, const std::string& uid);
	void notifyStateListener() const;

	std::multimap<std::string, std::weak_ptr<ContactRegisteredListener>> mContactListenersMap;
	std::list<std::shared_ptr<RegistrarDbStateListener>> mStateListeners;
	LocalRegExpire* mLocalRegExpire;
	std::string mMessageExpiresName;
	static std::unique_ptr<RegistrarDb> sUnique;
	Agent* mAgent;
	bool mWritable = false;
	bool mUseGlobalDomain;
	bool mGruuEnabled;
};

} // namespace flexisip
