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

#include "registrardb.hh"
#include "registrardb-internal.hh"
#ifdef ENABLE_REDIS
#include "registrardb-redis.hh"
#endif
#include "common.hh"

#include "configmanager.hh"

#include <sstream>
#include <ctime>
#include <cstdio>
#include <algorithm>

#include <sofia-sip/sip_protos.h>

using namespace ::std;

sip_contact_t *Record::extendedContactToSofia(su_home_t *home, const ExtendedContact &ec, time_t now) {
	sip_contact_t *contact = NULL;
	time_t expire = ec.mExpireAt - now;
	if (expire > 0) {
		if (ec.mQ == 0) {
			contact = sip_contact_format(home, "%s;expires=%lu", ec.mSipUri, expire);
		} else {
			contact = sip_contact_format(home, "%s;q=%4.2f;expires=%lu", ec.mSipUri, ec.mQ, expire);
		}
	}
	return contact;
}

const sip_contact_t *Record::getContacts(su_home_t *home, time_t now) {
	sip_contact_t *alist = NULL;
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		sip_contact_t *current = extendedContactToSofia(home, **it, now);
		if (current && alist) {
			current->m_next = alist;
		}
		alist = current;
	}
	return alist;
}

bool Record::isInvalidRegister(const char *call_id, uint32_t cseq) {
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		shared_ptr<ExtendedContact> ec = (*it);
		if ((0 == strcmp(ec->mCallId, call_id)) && cseq <= ec->mCSeq) {
			return true;
		}
	}
	return false;
}

/**
 * Should first have checked the validity of the register with isValidRegister.
 */
void Record::clean(const sip_contact_t *sip, const char *call_id, uint32_t cseq, time_t now) {
	char lineValue[20];
	char *lineValuePtr = lineValue;
	if (!url_param(sip->m_url[0].url_params, sLineFieldName.c_str(), lineValue, sizeof(lineValue) - 1)) {
		lineValuePtr = NULL;
	}
	auto it = mContacts.begin();
	while (it != mContacts.end()) {
		shared_ptr<ExtendedContact> ec = (*it);
		if (now >= ec->mExpireAt) {
			LOGD("Cleaning expired contact %s", ec->mContactId);
			it = mContacts.erase(it);
		} else if (ec->mLineValueCopy && lineValuePtr != NULL && 0 == strcmp(ec->mLineValueCopy, lineValuePtr)) {
			LOGD("Cleaning older line '%s' for contact %s", lineValuePtr, ec->mContactId);
			it = mContacts.erase(it);
		} else if (0 == strcmp(ec->mCallId, call_id)) {
			LOGD("Cleaning same call id contact %s", ec->mContactId);
			it = mContacts.erase(it);
		} else {
			++it;
		}
	}

	if (IS_LOGD)
		print();
}

/*
 static int countContacts(const sip_contact_t *contacts) {
 sip_contact_t *c=(sip_contact_t *)contacts;
 int count=0;
 for(;c;c=c->m_next) {
 ++count;
 }

 return count;
 }


 static bool ec_sort(ExtendedContact *ec1, ExtendedContact *ec2) {
 return ec1->mUpdatedTime < ec2->mUpdatedTime;
 }

 void Record::makeSpace(int slots) {
 int spaceNeeded=countContacts(contacts);

 int spaceLeft=sMaxContacts - mContacts.size() - count;
 if (spaceLeft >=0) return;

 LOGD("Need to make space for received contacts (need %i slots)", -spaceLeft);
 sort (mContacts.begin(), mContacts.end(), ec_sort);
 print();

 list<ExtendedContact *>::iterator it;
 for (it=mContacts.begin(); spaceLeft == 0; ++it) {
 it=mContacts.erase(it);
 ++spaceLeft;
 }
 print();
 }
 */

/**
 * Should first have checked the validity of the register with isValidRegister.
 */
void Record::clean(time_t now) {
	auto it = mContacts.begin();
	while (it != mContacts.end()) {
		shared_ptr<ExtendedContact> ec = (*it);
		if (now >= ec->mExpireAt) {
			it = mContacts.erase(it);
		} else {
			++it;
		}
	}
}

time_t Record::latestExpire() const {
	time_t latest=0;
	for (auto it=mContacts.begin(); it != mContacts.end(); ++it) {
		if ((*it)->mExpireAt > latest) latest=(*it)->mExpireAt;
	}
	return latest;
}

time_t Record::latestExpire(const std::string &route) const {
	time_t latest=0;
	for (auto it=mContacts.begin(); it != mContacts.end(); ++it) {
		if ((*it)->mRoute && (*it)->mExpireAt > latest && 0 == strcmp((*it)->mRoute, route.c_str()))
			latest=(*it)->mExpireAt;
	}
	return latest;
}

void Record::insertOrUpdateBinding(const shared_ptr<ExtendedContact> &ec) {
	// Try to locate an existing contact
	shared_ptr<ExtendedContact> olderEc;
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		if (0 == strcmp(ec->mContactId, (*it)->mContactId)) {
			LOGD("Removing older contact with same id %s", (*it)->mContactId);
			mContacts.erase(it);
			mContacts.push_back(ec);
			return;
		}
		if (!olderEc || olderEc->mUpdatedTime > (*it)->mUpdatedTime) {
			olderEc = (*it);
		}
	}

	// If contact doesn't exist and there is space left
	if (mContacts.size() < (unsigned int) sMaxContacts) {
		mContacts.push_back(ec);
	} else { // no space
		mContacts.remove(olderEc);
		mContacts.push_back(ec);
	}
}

static void defineContactId(ostringstream &oss, const url_t *url, const char *transport) {
	if (transport != NULL)
		oss << transport << ":";
	if (url->url_user != NULL)
		oss << url->url_user << ":";
	oss << url->url_host;
	if (url->url_port)
		oss << ":" << url->url_port;
}

void Record::bind(const sip_contact_t *contacts, const char* route, int globalExpire, const char *call_id, uint32_t cseq, time_t now, bool alias) {
	sip_contact_t *c = (sip_contact_t *) contacts;
	while (c) {
		char lineValue[20];
		char *lineValuePtr = lineValue;
		if (!url_param(c->m_url[0].url_params, sLineFieldName.c_str(), lineValue, sizeof(lineValue) - 1)) {
			lineValuePtr = NULL;
		}
		char transport[20];
		char *transportPtr = transport;
		if (!url_param(c->m_url[0].url_params, "transport", transport, sizeof(transport) - 1)) {
			transportPtr = NULL;
		}
		ostringstream contactId;
		defineContactId(contactId, c->m_url, transportPtr);
		insertOrUpdateBinding(make_shared<ExtendedContact>(c, contactId.str().c_str(), route, lineValuePtr, globalExpire, call_id, cseq, now, alias));
		c = c->m_next;
	}

	if (IS_LOGD)
		print();
}

void Record::bind(const char *c, const char *contactId, const char* route, const char *lineValue, long expireAt, float q, const char *call_id, uint32_t cseq, time_t updated_time, bool alias) {
	insertOrUpdateBinding(make_shared<ExtendedContact>(c, contactId, route, lineValue, expireAt, q, call_id, cseq, updated_time, alias));
}

void Record::print() {
	LOGD("Record contains %zu contacts", mContacts.size());
	time_t now=time(NULL);
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		shared_ptr<ExtendedContact> ec = (*it);
		char buffer[256] = "UNDETERMINED";
		struct tm *ptm = localtime(&ec->mExpireAt);
		if (ptm != NULL) {
			strftime(buffer, sizeof(buffer) - 1, "%c", ptm);
		}
		int expireAfter=ec->mExpireAt-now;
		LOGD("%s route=%s alias=%s expire=%d s (%s)",
				ec->mSipUri, ec->mRoute,
				ec->mAlias ? "yes" : "no",
				expireAfter, buffer);
	}
	LOGD("==========================");
}

int Record::sMaxContacts = -1;
string Record::sLineFieldName = "";

Record::Record(string key):mKey(key) {
	if (sMaxContacts == -1)
		init();
}

Record::~Record() {
}

void Record::init() {
	GenericStruct *registrar = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	sMaxContacts = registrar->get<ConfigInt>("max-contacts-by-aor")->read();
	sLineFieldName = registrar->get<ConfigString>("line-field-name")->read();
}

RegistrarDb::LocalRegExpire::LocalRegExpire(string preferedRoute) {
	mPreferedRoute=preferedRoute;
}

RegistrarDb::RegistrarDb(Agent *ag) : mLocalRegExpire(new LocalRegExpire(ag->getPreferredRoute())) {
}

RegistrarDb::~RegistrarDb() {
	delete mLocalRegExpire;
}

void RegistrarDb::LocalRegExpire::update(const Record &record) {
	unique_lock<mutex> lock(mMutex);
	time_t latest=record.latestExpire(mPreferedRoute);
	if (latest > 0) {
		auto it = mRegMap.find(record.getKey());
		if (it != mRegMap.end()) {
			(*it).second = latest;
		} else {
			mRegMap.insert(make_pair(record.getKey(), latest));
		}
	} else {
		mRegMap.erase(record.getKey());
	}
}

size_t RegistrarDb::LocalRegExpire::countActives() {
	return mRegMap.size();
}
void RegistrarDb::LocalRegExpire::removeExpiredBefore(time_t before) {
	unique_lock<mutex> lock(mMutex);

	for (auto it=mRegMap.begin(); it!=mRegMap.end(); ) {
		//LOGE("> %s [%lu]", (*it).first.c_str(), (*it).second-before);
		if ((*it).second <= before) {
			auto prevIt = it;
			++it;
			mRegMap.erase(prevIt);
		} else {
			++it;
		}
	}
}


int RegistrarDb::count_sip_contacts(const sip_contact_t *contact) {
	int count = 0;
	sip_contact_t *current = (sip_contact_t *) contact;
	while (current) {
		current = current->m_next;
		++count;
	}
	return count;
}

void RegistrarDb::defineKeyFromUrl(char *key, int len, const url_t *url) {
	snprintf(key, len - 1, "%s@%s", url->url_user, url->url_host);
}

bool RegistrarDb::errorOnTooMuchContactInBind(const sip_contact_t *sip_contact, const char *key, const shared_ptr<RegistrarDbListener> &listener) {
	if (count_sip_contacts(sip_contact) > Record::getMaxContacts()) {
		LOGD("Too many contacts in register %s %i > %i", key, count_sip_contacts(sip_contact), Record::getMaxContacts());
		return true;
	}

	return false;
}

RegistrarDb *RegistrarDb::sUnique = NULL;

RegistrarDb *RegistrarDb::get(Agent *ag) {
	if (sUnique == NULL) {
		GenericStruct *cr = GenericManager::get()->getRoot();
		GenericStruct *mr = cr->get<GenericStruct>("module::Registrar");
		string dbImplementation = mr->get<ConfigString>("db-implementation")->read();
		if ("internal" == dbImplementation) {
			LOGI("RegistrarDB implementation is internal");
			sUnique = new RegistrarDbInternal(ag);
#ifdef ENABLE_REDIS
		} else if ("redis-sync"==dbImplementation) {
			LOGI("RegistrarDB implementation is synchronous REDIS");
			sUnique=new RegistrarDbRedisSync(ag);
		} else if ("redis-async"==dbImplementation) {
			LOGI("RegistrarDB implementation is asynchronous REDIS");
			sUnique=new RegistrarDbRedisAsync(ag);
#endif
		} else {
			LOGF("unsupported implementation %s", dbImplementation.c_str())
		}
	}

	return sUnique;
}

void RegistrarDb::bind(const url_t* fromUrl, const sip_contact_t *sip_contact, const char * calld_id, uint32_t cs_seq, const char *route, int global_expire, bool alias, const shared_ptr<RegistrarDbListener> &listener) {
	doBind(fromUrl, sip_contact, calld_id, cs_seq, route, global_expire, alias, listener);
}

void RegistrarDb::clear(const sip_t *sip, const shared_ptr<RegistrarDbListener> &listener) {
	doClear(sip, listener);
}

class RecursiveRegistrarDbListener: public RegistrarDbListener, public enable_shared_from_this<RecursiveRegistrarDbListener> {
private:
	RegistrarDb *m_database;
	shared_ptr<RegistrarDbListener> m_original_listerner;
	Record *m_record;
	su_home_t m_home;
	int m_request;
	int m_step;
	const char *m_url;
	static int sMaxStep;
public:
	RecursiveRegistrarDbListener(RegistrarDb *database, const shared_ptr<RegistrarDbListener> &original_listerner, const url_t *url, int step = sMaxStep) :
			m_database(database), m_original_listerner(original_listerner), m_record(new Record("virtual_record")), m_request(1), m_step(step) {
		su_home_init(&m_home);
		m_url = url_as_string(&m_home, url);
	}

	~RecursiveRegistrarDbListener() {
		su_home_deinit(&m_home);
		delete m_record;
	}

	void onRecordFound(Record *r) {
		if (r != NULL) {
			for (auto it = r->mContacts.begin(); it != r->mContacts.end(); ++it) {
				shared_ptr<ExtendedContact> ec = *it;
				if (!ec->mAlias || m_step == 0) {
					LOGD("Step: %d\tFind contact %s for %s.", m_step, ec->mSipUri, m_url);
					m_record->mContacts.push_back(ec);
				} else {
					LOGD("Step: %d\tFind alias %s for %s. Try to fetch it.", m_step, ec->mSipUri, m_url);
					m_record->mContacts.push_back(ec);
					sip_contact_t *contact = sip_contact_format(&m_home, "%s", ec->mSipUri);
					if (contact != NULL) {
						++m_request;
						m_database->fetch(contact->m_url, make_shared<RecursiveRegistrarDbListener>(m_database, this->shared_from_this(), contact->m_url, m_step - 1), false);
					} else {
						LOGW("Can't create sip_contact of %s.", ec->mSipUri);
					}
				}
			}
		}
		if (check()) {
			LOGD("Step: %d\tNo contact found for %s", m_step, m_url);
			m_original_listerner->onRecordFound(NULL);
		}
	}

	void onError() {
		LOGW("Step: %d\tError during recursive fetch of %s", m_step, m_url);
		if (check()) {
			m_original_listerner->onError();
		}
	}

	void onInvalid() {
		LOGW("Step: %d\tInvalid during recursive fetch of %s", m_step, m_url);
		if (check()) {
			m_original_listerner->onInvalid();
		}
	}

private:
	bool check() {
		if (--m_request == 0) {
			if (m_record->mContacts.size() == 0) {
				return true;
			}
			m_original_listerner->onRecordFound(m_record);
		}
		return false;
	}
};

// Max recursive step
int RecursiveRegistrarDbListener::sMaxStep = 1;

void RegistrarDb::fetch(const url_t *url, const shared_ptr<RegistrarDbListener> &listener, bool recursive) {
	if (recursive) {
		doFetch(url, make_shared<RecursiveRegistrarDbListener>(this, listener, url));
	} else {
		doFetch(url, listener);
	}
}

void RegistrarDb::bind(const sip_t *sip, const char* route, int globalExpire, bool alias, const shared_ptr<RegistrarDbListener> &listener) {
	bind(sip->sip_from->a_url, sip->sip_contact, sip->sip_call_id->i_id, sip->sip_cseq->cs_seq, route, globalExpire, alias, listener);
}
