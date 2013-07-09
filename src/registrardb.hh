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
	std::string mLineValueCopy;
	std::list<std::string> mPath;

	ExtendedContactCommon(const char *contactId, const std::list<std::string> &path, const char* callId, const char *lineValue) {
		if (callId) mCallId = callId;
		mPath = path;
		if (lineValue) mLineValueCopy = lineValue;
		mContactId = contactId;
	}
	ExtendedContactCommon(const std::string &route) : mContactId(), mCallId(),mLineValueCopy(),mPath({route}) {};
};


struct ExtendedContact {
	class Record;
	friend class Record;
	std::string mContactId;
	std::string mCallId;
	std::string mLineValueCopy;
	std::list<std::string> mPath;
	std::string mSipUri;
	float mQ;
	time_t mExpireAt;
	time_t mUpdatedTime;
	uint32_t mCSeq;
	bool mAlias;

	inline const char *callId() { return mCallId.c_str(); }
	inline const char *line() { return mLineValueCopy.c_str(); }
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

	ExtendedContact(const ExtendedContactCommon &common,
			sip_contact_t *sip_contact, int global_expire, uint32_t cseq, time_t updateTime, bool alias) :
			mContactId(common.mContactId), mCallId(common.mCallId), mLineValueCopy(common.mLineValueCopy), mPath(common.mPath),
			mSipUri(),
			mQ(0), mUpdatedTime(updateTime), mCSeq(cseq), mAlias(alias) {

		{
		su_home_t home;
		su_home_init(&home);
		mSipUri = ExtendedContact::format_url(&home, sip_contact->m_url);
		su_home_destroy(&home);
		}

		if (sip_contact->m_q) {
			mQ = atof(sip_contact->m_q);
		}

		int expire = resolve_expire(sip_contact->m_expires, global_expire);
		if (expire == -1) SLOGA << "no global expire nor local contact expire found";
		mExpireAt = updateTime + expire;
	}

	ExtendedContact(const ExtendedContactCommon &common,
			const char *sipuri, long expireAt, float q, uint32_t cseq, time_t updateTime, bool alias) :
			mContactId(common.mContactId), mCallId(common.mCallId), mLineValueCopy(common.mLineValueCopy), mPath(common.mPath),
			mSipUri(sipuri),
			mQ(q), mExpireAt(expireAt), mUpdatedTime(updateTime), mCSeq(cseq), mAlias(alias){
	}

	ExtendedContact(const url_t *url, std::string route) :
			mContactId(), mCallId(), mLineValueCopy(), mPath({route}),
			mSipUri(),
			mQ(0), mExpireAt(LONG_MAX), mUpdatedTime(0), mCSeq(0), mAlias(false){

		su_home_t home;
		su_home_init(&home);
		mSipUri = ExtendedContact::format_url(&home, url);
		su_home_destroy(&home);
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

	std::ostream &print(std::ostream & stream, time_t now, time_t offset = 0) const;
};
/*
std::ostream &operator<<(std::ostream & stream, const ExtendedContact &ec) {
	return stream;
}
*/


class Record {
	friend class RecursiveRegistrarDbListener;
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
	static std::string extractUniqueId(const url_t *url);
	static sip_contact_t *extendedContactToSofia(su_home_t *home, const ExtendedContact &ec, time_t now);
	const sip_contact_t * getContacts(su_home_t *home, time_t now);
	bool isInvalidRegister(const char *call_id, uint32_t cseq);
	void clean(const sip_contact_t *sip, const char *call_id, uint32_t cseq, time_t time);
	void clean(time_t time);
	void update(const sip_contact_t *contacts, const sip_path_t *path, int globalExpire, const char *call_id, uint32_t cseq, time_t now, bool alias);
	void update(const ExtendedContactCommon &ecc, const char* sipuri, long int expireAt, float q, uint32_t cseq, time_t updated_time, bool alias);
	
	void print(std::ostream &stream) const;
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
			SipParams(const url_t* from, const sip_contact_t *contact,
					      const char *id, uint32_t seq, const sip_path_t *path)
			: from(from), contact(contact), call_id(id), cs_seq(seq), path(path) {
			}
		};

		const SipParams sip;
		const int global_expire;
		const bool alias;
		BindParameters(SipParams sip, int expire, bool alias)
		: sip(sip), global_expire(expire), alias(alias) {
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
				sip->sip_cseq->cs_seq, sip->sip_path),
			globalExpire, alias);
		doBind(mainParams, listener);
	}
	void clear(const sip_t *sip, const std::shared_ptr<RegistrarDbListener> &listener);
	void fetch(const url_t *url, const std::shared_ptr<RegistrarDbListener> &listener, bool recursive = false);
	void updateRemoteExpireTime(const std::string &key, time_t expireat);
	unsigned long countLocalActiveRecords() {
		return mLocalRegExpire->countActives();
	}
	void useGlobalDomain(bool useGlobalDomain);
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
