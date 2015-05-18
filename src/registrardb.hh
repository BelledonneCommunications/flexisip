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
#include "log/logmanager.hh"
#include "agent.hh"
#include <string>
#include <list>

#define AOR_KEY_SIZE 128

struct ExtendedContactCommon {
	std::string mContactId;
	std::string mCallId;
	std::string mUniqueId;
	std::list<std::string> mPath;

	ExtendedContactCommon(const char *contactId, const std::list<std::string> &path, const char* callId, const char *lineValue) {
		if (callId) mCallId = callId;
		mPath = path;
		if (lineValue) mUniqueId = lineValue;
		mContactId = contactId;
	}
	ExtendedContactCommon(const std::string &route) : mContactId(), mCallId(),mUniqueId(),mPath({route}) {}
};


struct ExtendedContact {
	class Record;
	friend class Record;

	std::string mContactId;
	std::string mCallId;
	std::string mUniqueId;
	std::list<std::string> mPath;
	std::string mSipUri;
	float mQ;
	time_t mExpireAt;
	time_t mUpdatedTime;
	uint32_t mCSeq;
	bool mAlias;
	std::list<std::string> mAcceptHeader;

	inline const char *callId() { return mCallId.c_str(); }
	inline const char *line() { return mUniqueId.c_str(); }
	inline const char *contactId() { return mContactId.c_str(); }
	inline const char *route() { return (mPath.empty() ? NULL : mPath.cbegin()->c_str()); }

	static int resolve_expire(const char *contact_expire, int global_expire) {
		if (contact_expire) {
			return atoi(contact_expire);
		} else {
			if(global_expire >= 0) {
				return global_expire;
			} else {
				return -1;
			}
		}
	}

	static std::string url_as_string(su_home_t *home, const url_t *url) {
		std::string res=::url_as_string(home, url);
		if (res.c_str() && res.c_str()[0] != '<') return "<" + res + ">";
		else return res;
	}
	ExtendedContact(const ExtendedContactCommon &common,
			sip_contact_t *sip_contact, int global_expire, uint32_t cseq, time_t updateTime, bool alias, const std::list<std::string> &acceptHeaders) :
			mContactId(common.mContactId), mCallId(common.mCallId), mUniqueId(common.mUniqueId), mPath(common.mPath),
			mSipUri(),
			mQ(0), mUpdatedTime(updateTime), mCSeq(cseq), mAlias(alias), mAcceptHeader(acceptHeaders) {

		{
		su_home_t home;
		su_home_init(&home);
		mSipUri = url_as_string(&home, sip_contact->m_url);
		su_home_destroy(&home);
		}

		if (sip_contact->m_q) {
			mQ = atof(sip_contact->m_q);
		}

		int expire = resolve_expire(sip_contact->m_expires, global_expire);
		if (expire == -1) LOGA("no global expire (%d) nor local contact expire (%s)found", global_expire, sip_contact->m_expires);
		mExpireAt = updateTime + expire;
	}

	ExtendedContact(const ExtendedContactCommon &common,
			const char *sipuri, long expireAt, float q, uint32_t cseq, time_t updateTime, bool alias, const std::list<std::string> &acceptHeaders) :
			mContactId(common.mContactId), mCallId(common.mCallId), mUniqueId(common.mUniqueId), mPath(common.mPath),
			mSipUri(sipuri),
			mQ(q), mExpireAt(expireAt), mUpdatedTime(updateTime), mCSeq(cseq), mAlias(alias), mAcceptHeader(acceptHeaders) {
	}

	ExtendedContact(const url_t *url, std::string route) :
			mContactId(), mCallId(), mUniqueId(), mPath({route}),
			mSipUri(),
			mQ(0), mExpireAt(LONG_MAX), mUpdatedTime(0), mCSeq(0), mAlias(false), mAcceptHeader({}) {

		su_home_t home;
		su_home_init(&home);
		mSipUri = url_as_string(&home, url);
		su_home_destroy(&home);
	}

	std::ostream &print(std::ostream & stream, time_t now, time_t offset = 0) const;

	sip_contact_t *toSofia(su_home_t *home, time_t now) const;
};



class Record {
	friend class RegistrarDb;
private:
	static void init();
	void insertOrUpdateBinding(const std::shared_ptr<ExtendedContact> &ec);
	std::list<std::shared_ptr<ExtendedContact>> mContacts;
	std::string mKey;

public:
	static std::list<std::string> sLineFieldNames;
	static int sMaxContacts;
protected:
	static char sStaticRecordVersion[100];
public:
	Record(std::string key);
	static std::string extractUniqueId(const sip_contact_t *contact);
	const std::shared_ptr<ExtendedContact> extractContactByUniqueId(std::string uid);
	const sip_contact_t * getContacts(su_home_t *home, time_t now);
	void pushContact(const std::shared_ptr<ExtendedContact> &ct) { mContacts.push_back(ct);}
	bool isInvalidRegister(const char *call_id, uint32_t cseq);
	void clean(const sip_contact_t *sip, const char *call_id, uint32_t cseq, time_t time);
	void clean(time_t time);
	void update(const sip_contact_t *contacts, const sip_path_t *path, int globalExpire, const char *call_id, uint32_t cseq, time_t now, bool alias, const std::list<std::string> accept);
	void update(const ExtendedContactCommon &ecc, const char* sipuri, long int expireAt, float q, uint32_t cseq, time_t updated_time, bool alias, const std::list<std::string> accept);

	void print(std::ostream &stream) const;
	bool isEmpty() { return mContacts.empty(); }
	const std::string &getKey() const {
		return mKey;
	}
	void setKey(const char *key) {
		mKey=key;
	}
	int count() {
		return mContacts.size();
	}
	const std::list<std::shared_ptr<ExtendedContact>> &getExtendedContacts() const {
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

	static std::list<std::string> route_to_stl(su_home_t *home, const sip_route_s *route);

	~Record();
};

template< typename TraitsT >
inline std::basic_ostream< char, TraitsT >& operator<< (
	std::basic_ostream< char, TraitsT >& strm, const Record &record)
{
	record.print(strm);
	return strm;
}


/**
 * A pure virtual class that is used by the registrarDB to notify the
 */
class RegistrarDbListener: public StatFinishListener {
public:
	virtual ~RegistrarDbListener();
	virtual void onRecordFound(Record *r) = 0;
	virtual void onError() = 0;
	virtual void onInvalid() = 0;
};


/**
 * A singleton class which holds records contact addresses associated with a from.
 * Both local and remote storage implementations exist.
 * It is used by the Registrar module.
 **/
class RegistrarDb {
	friend class ModuleRegistrar;
public:
	struct BindParameters {
		/**
		 * Parameter wrapper class that doesn't copy anything.
		 */ struct SipParams {
			const url_t* from;
			const sip_contact_t *contact;
			const char * call_id;
			const uint32_t cs_seq;
			const sip_path_t *path;
			const sip_accept_t *accept;
			SipParams(const url_t* ifrom, const sip_contact_t *icontact,
					      const char *iid, uint32_t iseq, const sip_path_t *ipath, const sip_accept_t *iaccept)
			: from(ifrom), contact(icontact), call_id(iid), cs_seq(iseq), path(ipath), accept(iaccept) {
			}
		};

		const SipParams sip;
		const int global_expire;
		const bool alias;
		BindParameters(SipParams isip, int iexpire, bool ialias)
		: sip(isip), global_expire(iexpire), alias(ialias) {
		}
	};
	static RegistrarDb *get(Agent *ag);
	void bind(const BindParameters &mainParams, const std::shared_ptr<RegistrarDbListener> &listener) {
		doBind(mainParams, listener);
	}
	void bind(const sip_t *sip, int globalExpire, bool alias, const std::shared_ptr<RegistrarDbListener> &listener) {

		BindParameters mainParams(
			BindParameters::SipParams(
				sip->sip_from->a_url,
				sip->sip_contact,
				sip->sip_call_id->i_id,
				sip->sip_cseq->cs_seq, sip->sip_path, sip->sip_accept),
			globalExpire, alias);
		doBind(mainParams, listener);
	}
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
	};
	virtual void doBind(const BindParameters &params, const std::shared_ptr<RegistrarDbListener> &listener)=0;
	virtual void doClear(const sip_t *sip, const std::shared_ptr<RegistrarDbListener> &listener)=0;
	virtual void doFetch(const url_t *url, const std::shared_ptr<RegistrarDbListener> &listener)=0;

	int count_sip_contacts(const sip_contact_t *contact);
	bool errorOnTooMuchContactInBind(const sip_contact_t *sip_contact, const char *key, const std::shared_ptr<RegistrarDbListener> &listener);
	void defineKeyFromUrl(char *key, int len, const url_t *url);
	RegistrarDb(const std::string &preferedRoute);
	virtual ~RegistrarDb();
	std::map<std::string, Record*> mRecords;
	LocalRegExpire *mLocalRegExpire;
	bool mUseGlobalDomain;
	static RegistrarDb *sUnique;
};

#endif
