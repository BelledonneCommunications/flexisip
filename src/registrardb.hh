/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010  Belledonne Communications SARL.

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

#ifndef registrardb_hh
#define registrardb_hh

#include <map>
#include <list>
#include <set>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <limits>
#include <mutex>

#include <sofia-sip/sip.h>
#include "agent.hh"

#define AOR_KEY_SIZE 128

class ExtendedContact {
public:
	su_home_t home;
	char *mSipUri;
	float mQ;
	time_t mExpireAt;
	time_t mUpdatedTime;
	char *mCallId;
	uint32_t mCSeq;
	char *mLineValueCopy;
	char *mRoute;
	char *mContactId;
	bool mAlias;
	void common_init(const char *contactId, const char *route, const char* callId, const char *lineValue) {
		if (callId) mCallId = su_strdup(&home, callId);
		if (lineValue) mLineValueCopy = su_strdup(&home, lineValue);
		if (route) mRoute = su_strdup(&home, route);
		mContactId = su_strdup(&home, contactId);

	}

	ExtendedContact(const sip_contact_t *sip_contact, const char *contactId, const char *route, const char *lineValue, int global_expire, const char *callId, uint32_t cseq, time_t updateTime, bool alias) :
			mQ(0), mUpdatedTime(updateTime), mCallId(NULL), mCSeq(cseq), mLineValueCopy(NULL), mRoute(NULL), mContactId(NULL), mAlias(alias) {
		su_home_init(&home);

		mSipUri = ExtendedContact::format_url(&home, sip_contact->m_url);

		if (sip_contact->m_q) {
			mQ = atof(sip_contact->m_q);
		}

		if (sip_contact->m_expires) {
			mExpireAt = updateTime + atoi(sip_contact->m_expires);
		} else {
			if(global_expire >= 0) {
				mExpireAt = updateTime + global_expire;
			} else {
				mExpireAt = std::numeric_limits<time_t>::max();
			}
		}

		common_init(contactId, route, callId, lineValue);
	}

	ExtendedContact(const char *sip_contact, const char *contactId, const char *route, const char *lineValue, long expireAt, float q, const char *callId, uint32_t cseq, time_t updateTime, bool alias) :
			mSipUri(NULL), mQ(q), mExpireAt(expireAt), mUpdatedTime(updateTime), mCallId(NULL), mCSeq(cseq), mLineValueCopy(NULL), mRoute(NULL), mContactId(NULL), mAlias(alias){
		su_home_init(&home);
		mSipUri = su_strdup(&home, sip_contact);
		common_init(contactId, route, callId, lineValue);
	}

	ExtendedContact(const url_t *url, const char *route) :
			mSipUri(NULL), mQ(0), mExpireAt(LONG_MAX), mUpdatedTime(0), mCallId(NULL), mCSeq(0), mLineValueCopy(NULL), mRoute(NULL), mContactId(NULL), mAlias(false){
		su_home_init(&home);
		mSipUri = ExtendedContact::format_url(&home, url);
		if (route) mRoute = su_strdup(&home, route);
	}

	static char* format_url(su_home_t *home, const url_t *url) {
		const char * port = (url->url_port) ? url->url_port : "5060";
		if (url->url_params) {
			if (url->url_user) {
				return su_sprintf(home, "<sip:%s@%s:%s;%s>", url->url_user, url->url_host, port, url->url_params);
			} else {
				return su_sprintf(home, "<sip:%s:%s;%s>", url->url_host, port, url->url_params);
			}
		} else {
			if (url->url_user) {
				return su_sprintf(home, "<sip:%s@%s:%s>", url->url_user, url->url_host, port);
			} else {
				return su_sprintf(home, "<sip:%s:%s>", url->url_host, port);
			}
		}
	}

	~ExtendedContact() {
		su_home_destroy(&home);
	}

};

class Record {
	friend class RecursiveRegistrarDbListener;
	friend class RegistrarDb;
private:
	static void init();
	void insertOrUpdateBinding(const std::shared_ptr<ExtendedContact> &ec);
	std::list<std::shared_ptr<ExtendedContact>> mContacts;
	
	static std::list<std::string> sLineFieldNames;
	static int sMaxContacts;
	std::string mKey;
protected:
	static char sStaticRecordVersion[100];
public:
	Record(std::string key);
	static std::string extractUniqueId(const sip_contact_t *contact);
	static std::string extractUniqueId(const url_t *url);
	static sip_contact_t *extendedContactToSofia(su_home_t *home, const ExtendedContact &ec, time_t now);
	const sip_contact_t * getContacts(su_home_t *home, time_t now);
	bool isInvalidRegister(const char *call_id, uint32_t cseq);
	void clean(const sip_contact_t *sip, const char *call_id, uint32_t cseq, time_t time);
	void clean(time_t time);
	void bind(const sip_contact_t *contacts, const char* route, int globalExpire, const char *call_id, uint32_t cseq, time_t now, bool alias);
	void bind(const char *contact, const char* route, const char *transport, const char *lineValue, long expireAt, float q, const char *call_id, uint32_t cseq, time_t now, bool alias);
	void print();
	bool isEmpty() { return mContacts.empty(); };
	const std::string &getKey() const {
		return mKey;
	}
	void setKey(const char *key) {
		mKey=key;
	}
	int count() {
		return mContacts.size();
	}
	const std::list<std::shared_ptr<ExtendedContact>> &getExtendedContacts() {
		return mContacts;
	}
	static int getMaxContacts() {
		if (sMaxContacts == -1)
			init();
		return sMaxContacts;
	}
	time_t latestExpire() const;
	time_t latestExpire(const std::string &route) const;
	static void setStaticRecordsVersion(int version) {
		static int maxlen=sizeof(sStaticRecordVersion);
		memset(sStaticRecordVersion, 0, maxlen);
		if (version != 0) {
			snprintf(sStaticRecordVersion, maxlen, "static-record-v%d", version);
		}
	}

	~Record();
};

class RegistrarDbListener: public StatFinishListener {
public:
	~RegistrarDbListener() {
	}
	virtual void onRecordFound(Record *r) = 0;
	virtual void onError() = 0;
	virtual void onInvalid() {
		/*let the registration timeout;*/
	}
};


/**
 * A singleton class which holds records contact addresses associated with a from.
 * Both local and remote storage implementations exist.
 * It is used by the Registrar module.
 **/
class RegistrarDb {
	friend class Registrar;
public:
	static RegistrarDb *get(Agent *ag);
	void bind(const url_t* fromUrl, const sip_contact_t *sip_contact, const char * calld_id, uint32_t cs_seq, const char *route, int global_expire, bool alias, const std::shared_ptr<RegistrarDbListener> &listener);
	void bind(const sip_t *sip, const char* route, int global_expire, bool alias, const std::shared_ptr<RegistrarDbListener> &listener);
	void clear(const sip_t *sip, const std::shared_ptr<RegistrarDbListener> &listener);
	void fetch(const url_t *url, const std::shared_ptr<RegistrarDbListener> &listener, bool recursive = false);
	void updateRemoteExpireTime(const std::string &key, time_t expireat);
	unsigned long countLocalActiveRecords() {
		return mLocalRegExpire->countActives();
	}
protected:
	class LocalRegExpire {
		std::map<std::string, time_t> mRegMap;
		std::mutex mMutex;
		std::string mPreferedRoute;
	public:
		void remove(const std::string key) {
			mRegMap.erase(key);
		}
		void update(const Record &record);
		size_t countActives();
		void removeExpiredBefore(time_t before);
		LocalRegExpire(std::string preferedRoute);
	};
	virtual void doBind(const url_t* fromUrl, const sip_contact_t *sip_contact, const char * calld_id, uint32_t cs_seq, const char *route, int global_expire, bool alias, const std::shared_ptr<RegistrarDbListener> &listener)=0;
	virtual void doClear(const sip_t *sip, const std::shared_ptr<RegistrarDbListener> &listener)=0;
	virtual void doFetch(const url_t *url, const std::shared_ptr<RegistrarDbListener> &listener)=0;

	int count_sip_contacts(const sip_contact_t *contact);
	bool errorOnTooMuchContactInBind(const sip_contact_t *sip_contact, const char *key, const std::shared_ptr<RegistrarDbListener> &listener);
	void defineKeyFromUrl(char *key, int len, const url_t *url);
	RegistrarDb(Agent *ag);
	virtual ~RegistrarDb();
	std::map<std::string, Record*> mRecords;
	LocalRegExpire *mLocalRegExpire;
	bool mUseGlobalDomain;
	static RegistrarDb *sUnique;
};

#endif
