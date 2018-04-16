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
#include <iosfwd>

#include <sofia-sip/sip.h>
#include <sofia-sip/url.h>
#include <sofia-sip/su_random.h>
#include "log/logmanager.hh"
#include "agent.hh"
#include "module.hh"

#define AOR_KEY_SIZE 128

class ContactUpdateListener;

struct ExtendedContactCommon {
	std::string mContactId;
	std::string mCallId;
	std::string mUniqueId;
	std::list<std::string> mPath;

	ExtendedContactCommon(const char *contactId, const std::list<std::string> &path, const std::string &callId,
			const char *lineValue) {
		if (!callId.empty())
			mCallId = callId;
		mPath = path;
		if (lineValue)
			mUniqueId = lineValue;
		mContactId = contactId;
	}
	ExtendedContactCommon(const std::string &route) : mContactId(), mCallId(), mUniqueId(), mPath({route}) {
	}
};

struct ExtendedContact {
	class Record;
	friend class Record;

	std::string mContactId;
	std::string mCallId;
	std::string mUniqueId;
	std::list<std::string> mPath; //list of urls as string (not enclosed with brakets)
	sip_contact_t *mSipContact; // Full contact
	float mQ;
	time_t mExpireAt;
	time_t mExpireNotAtMessage;  // real expires time but not for message
	time_t mUpdatedTime;
	uint32_t mCSeq;
	bool mAlias;
	std::list<std::string> mAcceptHeader;
	bool mUsedAsRoute; /*whether the contact information shall be used as a route when forming a request, instead of
						  replacing the request-uri*/
	uint64_t mRegId; // a unique id shared with associate t_port
	SofiaAutoHome mHome;

	inline const char *callId() {
		return mCallId.c_str();
	}
	inline const char *line() {
		return mUniqueId.c_str();
	}
	inline const char *contactId() {
		return mContactId.c_str();
	}
	inline const char *route() {
		return (mPath.empty() ? NULL : mPath.cbegin()->c_str());
	}

	static int resolveExpire(const char *contact_expire, int global_expire) {
		if (contact_expire) {
			return atoi(contact_expire);
		} else {
			if (global_expire >= 0) {
				return global_expire;
			} else {
				return -1;
			}
		}
	}

	static std::string urlToString(const url_t *url) {
		std::ostringstream ostr;
		SofiaAutoHome home;
		char *tmp = url_as_string(home.home(), url);
		return std::string(tmp ? tmp : "");
	}
	//This function ensures compatibility with old redis record where url was stored with brakets.
	static std::string compatUrlToString(const char *url){
		if (url[0] == '<' && url[1] != '\0'){
			return std::string(url, 1, strlen(url)-2);
		}
		return std::string(url);
	}

	const std::string &getUniqueId() {
		return (mUniqueId.empty() ? mCallId : mUniqueId);
	}
	
	time_t getExpireNotAtMessage() {
		return mExpireNotAtMessage;
	}

	std::string serializeAsUrlEncodedParams();

	std::string getOrgLinphoneSpecs();

	void setupRegid();
	void transferRegId(const std::shared_ptr<ExtendedContact> &oldEc);
	const std::string getMessageExpires(const msg_param_t *m_params);

	ExtendedContact(const ExtendedContactCommon &common, sip_contact_t *sip_contact, int global_expire, uint32_t cseq,
					time_t updateTime, bool alias, const std::list<std::string> &acceptHeaders)
		: mContactId(common.mContactId), mCallId(common.mCallId), mUniqueId(common.mUniqueId), mPath(common.mPath),
			mSipContact(NULL), mQ(1.0), mUpdatedTime(updateTime), mCSeq(cseq), mAlias(alias), mAcceptHeader(acceptHeaders),
			mUsedAsRoute(false), mRegId(0), mHome() {

		mSipContact = sip_contact_dup(mHome.home(), sip_contact);
		mSipContact->m_next = NULL;

		if (mSipContact->m_q) {
			mQ = atof(mSipContact->m_q);
		}

		int expire = resolveExpire(mSipContact->m_expires, global_expire);
		mExpireNotAtMessage = updateTime + expire;
		expire = resolveExpire(getMessageExpires(mSipContact->m_params).c_str(), expire);
		if (expire == -1) {
			LOGE("no global expire (%d) nor local contact expire (%s)found", global_expire, mSipContact->m_expires);
			expire = 0;
		}
		mExpireAt = updateTime + expire;
		mExpireAt = mExpireAt > mExpireNotAtMessage ? mExpireAt:mExpireNotAtMessage;
	}

	ExtendedContact(const url_t *url, const std::string &route, const float q = 1.0)
	: mContactId(), mCallId(), mUniqueId(), mPath({route}), mSipContact(NULL), mQ(q), mExpireAt(LONG_MAX),
		mExpireNotAtMessage(LONG_MAX), mUpdatedTime(0), mCSeq(0), mAlias(false), mAcceptHeader({}), mUsedAsRoute(false),
		mRegId(0), mHome() {
		mSipContact = sip_contact_create(mHome.home(), (url_string_t*)url, NULL);
	}
	
	ExtendedContact(const ExtendedContact &ec)
		: mContactId(ec.mContactId), mCallId(ec.mCallId), mUniqueId(ec.mUniqueId), mPath(ec.mPath), mSipContact(NULL), mQ(ec.mQ),
		mExpireAt(ec.mExpireAt), mExpireNotAtMessage(ec.mExpireNotAtMessage), mUpdatedTime(ec.mUpdatedTime), mCSeq(ec.mCSeq),
		mAlias(ec.mAlias), mAcceptHeader(ec.mAcceptHeader), mUsedAsRoute(ec.mUsedAsRoute), mRegId(ec.mRegId), mHome() {
		mSipContact = sip_contact_dup(mHome.home(), ec.mSipContact);
		mSipContact->m_next = NULL;
	}

	std::ostream &print(std::ostream &stream, time_t _now = getCurrentTime(), time_t offset = 0) const;
	sip_contact_t *toSofiaContact(su_home_t *home, time_t now) const;
	sip_route_t *toSofiaRoute(su_home_t *home) const;
	/*returns a new url_t where regid (private flexisip parameter) is removed*/
	url_t *toSofiaUrlClean(su_home_t *home);
};

template <typename TraitsT>
inline std::basic_ostream<char, TraitsT> &operator<<(std::basic_ostream<char, TraitsT> &strm, const ExtendedContact &ec) {
	ec.print(strm);
	return strm;
}

class Record {
	friend class RegistrarDb;

  private:
	static void init();
	void insertOrUpdateBinding(const std::shared_ptr<ExtendedContact> &ec, const std::shared_ptr<ContactUpdateListener> &listener);
	std::list<std::shared_ptr<ExtendedContact>> mContacts;
	std::list<std::shared_ptr<ExtendedContact>> mContactsToRemove;
	std::string mKey;
	bool mIsDomain; /*is a domain registration*/
	bool mOnlyStaticContacts;

  public:
	static std::list<std::string> sLineFieldNames;
	static int sMaxContacts;
	static bool sAssumeUniqueDomains;
	Record(const url_t *aor);
	static std::string extractUniqueId(const sip_contact_t *contact);
	const std::shared_ptr<ExtendedContact> extractContactByUniqueId(std::string uid);
	sip_contact_t *getContacts(su_home_t *home, time_t now);
	void pushContact(const std::shared_ptr<ExtendedContact> &ct) {
		mContacts.push_back(ct);
	}
	std::list<std::shared_ptr<ExtendedContact>>::iterator removeContact(const std::shared_ptr<ExtendedContact> &ct) {
		return mContacts.erase(find(mContacts.begin(), mContacts.end(), ct));
	}
	bool isInvalidRegister(const std::string &call_id, uint32_t cseq);
	void clean(time_t time, const std::shared_ptr<ContactUpdateListener> &listener);
	void update(sip_contact_t *contacts, const sip_path_t *path, int globalExpire, const std::string &call_id,
				uint32_t cseq, time_t now, bool alias, const std::list<std::string> accept, bool usedAsRoute,
				const std::shared_ptr<ContactUpdateListener> &listener);
	//Deprecated: this one is used by protobuf serializer
	void update(const ExtendedContactCommon &ecc, const char *sipuri, long int expireAt, float q, uint32_t cseq,
				time_t updated_time, bool alias, const std::list<std::string> accept, bool usedAsRoute,
				const std::shared_ptr<ContactUpdateListener> &listener);
	bool updateFromUrlEncodedParams(const char *key, const char *uid, const char *full_url);

	void print(std::ostream &stream) const;
	bool isEmpty() const {
		return mContacts.empty();
	}
	const std::string &getKey() const {
		return mKey;
	}
	int count() {
		return mContacts.size();
	}
	const std::list<std::shared_ptr<ExtendedContact>> &getExtendedContacts() const {
		return mContacts;
	}
	const std::list<std::shared_ptr<ExtendedContact>> &getContactsToRemove() const {
		return mContactsToRemove;
	}
	void cleanContactsToRemoveList() {
		mContactsToRemove.clear();
	}
	/**
	 * Check if the contacts list size is < to max aor config option and remove older contacts to match restriction if needed
	 */
	void applyMaxAor();
	static int getMaxContacts() {
		if (sMaxContacts == -1)
			init();
		return sMaxContacts;
	}
	time_t latestExpire() const;
	time_t latestExpire(const std::string &route) const;
	static std::list<std::string> route_to_stl(const sip_route_s *route);
	void appendContactsFrom(Record *src);
	static std::string defineKeyFromUrl(const url_t *aor);
	~Record();

	bool haveOnlyStaticContacts() const {
		return mOnlyStaticContacts;
	}
};

template <typename TraitsT>
inline std::basic_ostream<char, TraitsT> &operator<<(std::basic_ostream<char, TraitsT> &strm, const Record &record) {
	record.print(strm);
	return strm;
}

/**
 * A pure virtual class that is used by the registrarDB to notify the
 */
class RegistrarDbListener : public StatFinishListener {
  public:
	virtual ~RegistrarDbListener();
	virtual void onRecordFound(Record *r) = 0;
	virtual void onError() = 0;
	virtual void onInvalid() = 0;
};

class ContactUpdateListener : public RegistrarDbListener {
	public:
	virtual ~ContactUpdateListener();
	virtual void onContactUpdated(const std::shared_ptr<ExtendedContact> &ec) = 0;
};

class ContactRegisteredListener {
  public:
	virtual ~ContactRegisteredListener();
	virtual void onContactRegistered(std::string key, std::string uid) = 0;
};

class LocalRegExpireListener {
public:
	virtual ~LocalRegExpireListener();
	virtual void onLocalRegExpireUpdated(unsigned int count) = 0;
};

/**
 * A singleton class which holds records contact addresses associated with a from.
 * Both local and remote storage implementations exist.
 * It is used by the Registrar module.
 **/
class RegistrarDb {
	friend class ModuleRegistrar;

  public:
	static RegistrarDb *initialize(Agent *ag);
	static RegistrarDb *get();
	void bind(const url_t *ifrom, sip_contact_t *icontact, const char *iid, uint32_t iseq,
					  const sip_path_t *ipath, const sip_supported_t *isupported, const sip_accept_t *iaccept, bool usedAsRoute, int expire, bool alias, int version, const std::shared_ptr<ContactUpdateListener> &listener);
	void bind(const sip_t *sip, int globalExpire, bool alias, int version, const std::shared_ptr<ContactUpdateListener> &listener);
	void clear(const sip_t *sip, const std::shared_ptr<ContactUpdateListener> &listener);
	void fetch(const url_t *url, const std::shared_ptr<ContactUpdateListener> &listener, bool recursive = false);
	void fetch(const url_t *url, const std::shared_ptr<ContactUpdateListener> &listener, bool includingDomains, bool recursive);
	void fetchForGruu(const url_t *url, const std::string &gruu, const std::shared_ptr<ContactUpdateListener> &listener);
	void updateRemoteExpireTime(const std::string &key, time_t expireat);
	unsigned long countLocalActiveRecords() {
		return mLocalRegExpire->countActives();
	}

	void notifyContactListener(const std::string &key, const std::string &uid);
	virtual void subscribe(const std::string &topic, const std::shared_ptr<ContactRegisteredListener> &listener);
	virtual void unsubscribe(const std::string &topic);
	virtual void publish(const std::string &topic, const std::string &uid) = 0;
	bool useGlobalDomain()const{
		return mUseGlobalDomain;
	}
	const std::string &messageExpiresName() {
		return mMessageExpiresName;
	}
	const std::string getMessageExpires(const msg_param_t *m_params);

	void subscribeLocalRegExpire(LocalRegExpireListener *listener) {
		mLocalRegExpire->subscribe(listener);
	}
	void unsubscribeLocalRegExpire(LocalRegExpireListener *listener) {
		mLocalRegExpire->unsubscribe(listener);
	}
  protected:
	class LocalRegExpire {
		std::map<std::string, time_t> mRegMap;
		std::mutex mMutex;
		std::string mPreferedRoute;
		std::list<LocalRegExpireListener *> mLocalRegListenerList;

	  public:
		void remove(const std::string key) {
			std::lock_guard<std::mutex> lock(mMutex);
			mRegMap.erase(key);
		}
		void update(const Record &record);
		size_t countActives();
		void removeExpiredBefore(time_t before);
		LocalRegExpire(std::string preferedRoute);
		void clearAll() {
			std::lock_guard<std::mutex> lock(mMutex);
			mRegMap.clear();
		}

		void subscribe(LocalRegExpireListener *listener);
		void unsubscribe(LocalRegExpireListener *listener);
		void notifyLocalRegExpireListener(unsigned int count);
	};
	virtual void doBind(const url_t *ifrom, sip_contact_t *icontact, const char *iid, uint32_t iseq,
					  const sip_path_t *ipath, std::list<std::string> acceptHeaders, bool usedAsRoute, int expire, int alias, int version, const std::shared_ptr<ContactUpdateListener> &listener) = 0;
	virtual void doClear(const sip_t *sip, const std::shared_ptr<ContactUpdateListener> &listener) = 0;
	virtual void doFetch(const url_t *url, const std::shared_ptr<ContactUpdateListener> &listener) = 0;
	virtual void doFetchForGruu(const url_t *url, const std::string &gruu, const std::shared_ptr<ContactUpdateListener> &listener) = 0;
	virtual void doMigration() = 0;

	int count_sip_contacts(const sip_contact_t *contact);
	bool errorOnTooMuchContactInBind(const sip_contact_t *sip_contact, const std::string &key,
									 const std::shared_ptr<RegistrarDbListener> &listener);
	void fetchWithDomain(const url_t *url, const std::shared_ptr<ContactUpdateListener> &listener, bool recursive);
	RegistrarDb(const std::string &preferedRoute);
	virtual ~RegistrarDb();
	std::map<std::string, Record *> mRecords;
	std::map<std::string, std::shared_ptr<ContactRegisteredListener>> mContactListenersMap;
	LocalRegExpire *mLocalRegExpire;
	bool mUseGlobalDomain;
	std::string mMessageExpiresName;
	static RegistrarDb *sUnique;
};

#endif
