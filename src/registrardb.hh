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
#include <string>
#include <cstdio>
#include <cstdlib>
#include <algorithm>

#include <sofia-sip/sip.h>
#include "agent.hh"

#define AOR_KEY_SIZE 128

typedef struct extended_contact {
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

	void common_init(const char *contactId, const char *route, const char* callId, const char *lineValue){
		mCallId=su_strdup(&home, callId);
		if (lineValue) mLineValueCopy=su_strdup(&home,lineValue);
		if (route) mRoute=su_strdup(&home,route);
		mContactId=su_strdup(&home, contactId);

	}
	extended_contact(const sip_contact_t *sip_contact, const char *contactId, const char *route, const char *lineValue, int global_expire, const char *callId, uint32_t cseq, time_t updateTime):
			mQ(0),mUpdatedTime(updateTime),mCallId(NULL),mCSeq(cseq),mLineValueCopy(NULL),mRoute(NULL),mContactId(NULL) {
		su_home_init(&home);

		const url_t *url=sip_contact->m_url;
		if (url->url_params){
			if (url->url_user) {
				mSipUri=su_sprintf(&home, "<sip:%s@%s:%s;%s>", url->url_user, url->url_host, url->url_port, url->url_params);
			} else {
				mSipUri=su_sprintf(&home, "<sip:%s:%s;%s>", url->url_host, url->url_port, url->url_params);
			}
		} else {
			if (url->url_user) {
				mSipUri=su_sprintf(&home,"<sip:%s@%s:%s>", url->url_user, url->url_host, url->url_port);
			} else {
				mSipUri=su_sprintf(&home,"<sip:%s:%s>", url->url_host, url->url_port);
			}
		}

		if (sip_contact->m_q){
			mQ=atof(sip_contact->m_q);
		}

		if (sip_contact->m_expires){
			mExpireAt=updateTime+atoi(sip_contact->m_expires);
		} else {
			mExpireAt=updateTime+global_expire;
		}

		common_init(contactId, route, callId, lineValue);
	}

	extended_contact(const char *sip_contact, const char *contactId, const char *route, const char *lineValue, long expireAt, float q, const char *callId, uint32_t cseq, time_t updateTime)
			:mSipUri(NULL),mQ(q),mExpireAt(expireAt),mUpdatedTime(updateTime),
			mCallId(NULL),mCSeq(cseq),mLineValueCopy(NULL),mRoute(NULL),mContactId(NULL){
		su_home_init(&home);
		mSipUri=su_strdup(&home, sip_contact);
		common_init(contactId, route, callId, lineValue);
	}
	~extended_contact(){
		su_home_destroy(&home);
	}

} extended_contact;



class Record{
	static void init();
	void insertOrUpdateBinding(extended_contact *ec);
	std::list<extended_contact *> mContacts;
	static std::string sLineFieldName;
	static int sMaxContacts;
	public:
		Record();
		static sip_contact_t *extendedContactToSofia(su_home_t *home, extended_contact *ec, time_t now);
		const sip_contact_t * getContacts(su_home_t *home, time_t now);
		bool isInvalidRegister(const char *call_id, uint32_t cseq);
		void clean(sip_contact_t *sip, const char *call_id, uint32_t cseq, time_t time);
		void clean(time_t time);
		void bind(const sip_contact_t *contacts, const char* route, int globalExpire, const char *call_id, uint32_t cseq, time_t now);
		void bind(const char *contact, const char* route, const char *transport, const char *lineValue, long expireAt, float q, const char *call_id, uint32_t cseq, time_t now);
		void print();
		int count(){return mContacts.size();}
		std::list<extended_contact *> &getExtendedContacts() {return mContacts;}
		static int getMaxContacts(){
			if (sMaxContacts == -1) init();
			return sMaxContacts;}
		~Record();
};


class RegistrarDbListener {
public:
	~RegistrarDbListener(){}
	virtual void onRecordFound(Record *r)=0;
	virtual void onError()=0;
	virtual void onInvalid(){/*let the registration timeout;*/};
};

/**
 * A singleton class which holds records contact addresses associated with a from.
 * Both local and remote storage implementations exist.
 * It is used by the Registrar module.
**/
class RegistrarDb{
	public:
		static RegistrarDb *get(Agent *ag);
		virtual void bind(const sip_t *sip, const char* route, int global_expire, RegistrarDbListener *listener)=0;
		virtual void clear(const sip_t *sip, RegistrarDbListener *listener)=0;
		virtual void fetch(const url_t *url, RegistrarDbListener *listener)=0;
	protected:
		int count_sip_contacts(const sip_contact_t *contact);
		bool errorOnTooMuchContactInBind(const sip_t *sip, const char *key, RegistrarDbListener *listener);
		static void defineKeyFromUrl(char *key, int len, const url_t *url);
		RegistrarDb();
		std::map<std::string,Record*> mRecords;
		static RegistrarDb *sUnique;
};


#endif
