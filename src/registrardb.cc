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

#include "registrardb.hh"
#include "registrardb-internal.hh"
#ifdef ENABLE_REDIS
#include "registrardb-redis.hh"
#endif
#include "common.hh"

#include "configmanager.hh"

#include <sstream>
#include <ostream>
#include <ctime>
#include <cstdio>
#include <algorithm>
#include <iomanip>

#include <sofia-sip/sip_protos.h>
#include "recordserializer.hh"
#include "module.hh"

using namespace std;

ostream &ExtendedContact::print(std::ostream &stream, time_t _now, time_t _offset) const {
	time_t now = _now;
	time_t offset = _offset;
	char buffer[256] = "UNDETERMINED";
	time_t expire = mExpireAt;
	expire += offset;
	struct tm *ptm = localtime(&expire);
	if (ptm != NULL) {
		strftime(buffer, sizeof(buffer) - 1, "%c", ptm);
	}
	int expireAfter = mExpireAt - now;

	stream << urlToString(mSipContact->m_url) << " path=\"";
	for (auto it = mPath.cbegin(); it != mPath.cend(); ++it) {
		if (it != mPath.cbegin())
			stream << " ";
		stream << *it;
	}
	stream << "\"";
	stream << " alias=" << (mAlias ? "yes" : "no");
	if (!mAlias)
		stream << " uid=" << mUniqueId;
	stream << " expire=" << expireAfter << " s (" << buffer << ")";
	return stream;
}

void ExtendedContact::transferRegId(const std::shared_ptr<ExtendedContact> &oldEc) {
	// Transfert param RegId from oldEc to this
	char strRegid[32] = {0};
	if (oldEc->mRegId > 0 &&
			(url_param(mSipContact->m_url->url_params, "regid", strRegid, sizeof(strRegid) - 1) > 0 &&
			std::strtoull(strRegid, NULL, 16) != oldEc->mRegId)
		) {
		std::ostringstream os;
		os << "regid=" << std::hex << oldEc->mRegId;
		mSipContact->m_url->url_params = url_strip_param_string(su_strdup(mHome.home(), mSipContact->m_url->url_params), "regid");
		url_param_add(mHome.home(), mSipContact->m_url, os.str().c_str());
		this->mRegId = oldEc->mRegId;
	}
}

url_t *ExtendedContact::toSofiaUrlClean(su_home_t *home){
	url_t *ret = NULL;
	if (!mSipContact)
		return NULL;

	ret = url_hdup(home, mSipContact->m_url);
	ret->url_params = url_strip_param_string((char*)ret->url_params, "regid");
	return ret;
}

string ExtendedContact::getOrgLinphoneSpecs() {
	if (!mSipContact) return string();
	const char *specs = msg_params_find(mSipContact->m_params, "+org.linphone.specs");
	string result = specs ? string(specs) : string();
	return result;
}
const std::string ExtendedContact::getMessageExpires(const msg_param_t *m_params)  {
	if(m_params) {
		// Find message expires time in the contact parameters
		std::string mss_expires(*m_params);
		std::string name_expires_mss = RegistrarDb::get()->messageExpiresName();
		if (mss_expires.find(name_expires_mss+"=") != std::string::npos){
			mss_expires = mss_expires.substr(mss_expires.find(name_expires_mss+"=")+(strlen(name_expires_mss.c_str())+1));
			return mss_expires;
		}
	}
	return "";
}

sip_contact_t *ExtendedContact::toSofiaContact(su_home_t *home, time_t now) const {
	time_t expire = mExpireAt - now;
	if (expire <= 0)
		return NULL;

	mSipContact->m_next = NULL;
	return sip_contact_dup(home, mSipContact);
}

sip_route_t *ExtendedContact::toSofiaRoute(su_home_t *home) const {
	sip_route_t *rbegin = NULL;
	sip_route_t *r = NULL;
	for (auto it = mPath.begin(); it != mPath.end(); ++it) {
		sip_route_t *newr = sip_route_format(home, "<%s>", (*it).c_str());
		if (!newr) {
			LOGE("Cannot parse %s into route header", (*it).c_str());
			break;
		}
		if (!url_has_param(newr->r_url, "lr")) {
			url_param_add(home, newr->r_url, "lr");
		}
		if (rbegin == NULL) {
			rbegin = newr;
		} else {
			r->r_next = newr;
		}
		r = newr;
	}
	return rbegin;
}

sip_contact_t *Record::getContacts(su_home_t *home, time_t now) {
	sip_contact_t *alist = NULL;
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		sip_contact_t *current = (*it)->toSofiaContact(home, now);
		if (current && alist) {
			current->m_next = alist;
		}
		alist = current;
	}
	return alist;
}

bool Record::isInvalidRegister(const std::string &call_id, uint32_t cseq) {
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		shared_ptr<ExtendedContact> ec = (*it);
		if ((0 == strcmp(ec->callId(), call_id.c_str())) && cseq <= ec->mCSeq) {
			LOGD("CallID %s already registered with CSeq %d (received %d)", call_id.c_str(), ec->mCSeq, cseq);
			return true;
		}
	}
	return false;
}

string Record::extractUniqueId(const sip_contact_t *contact) {
	char lineValue[256] = {0};

	/*search for device unique parameter among the ones configured */
	for (auto it = sLineFieldNames.begin(); it != sLineFieldNames.end(); ++it) {
		const char *ct_param = msg_params_find(contact->m_params, it->c_str());
		if (ct_param)
			return ct_param;
		if (url_param(contact->m_url->url_params, it->c_str(), lineValue, sizeof(lineValue) - 1) > 0) {
			return lineValue;
		}
	}

	return "";
}

const shared_ptr<ExtendedContact> Record::extractContactByUniqueId(std::string uid) {
	const auto contacts = getExtendedContacts();
	for (auto it = contacts.begin(); it != contacts.end(); ++it) {
		const shared_ptr<ExtendedContact> ec = *it;
		if (ec && ec->mUniqueId.compare(uid) == 0) {
			return ec;
		}
	}
	shared_ptr<ExtendedContact> noContact;
	return noContact;
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
void Record::clean(time_t now, const std::shared_ptr<ContactUpdateListener> &listener) {
	auto it = mContacts.begin();
	while (it != mContacts.end()) {
		shared_ptr<ExtendedContact> ec = (*it);
		if (now >= ec->mExpireAt) {
			if (listener)
				listener->onContactUpdated(ec);
			it = mContacts.erase(it);
		} else {
			++it;
		}
	}
}

time_t Record::latestExpire() const {
	time_t latest = 0;
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		if ((*it)->mExpireAt > latest)
			latest = (*it)->mExpireAt;
	}
	return latest;
}

time_t Record::latestExpire(const std::string &route) const {
	time_t latest = 0;
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		if ((*it)->mPath.empty() || (*it)->mExpireAt <= latest)
			continue;
		if (*(*it)->mPath.begin() == route)
			latest = (*it)->mExpireAt;
	}
	return latest;
}

std::list<std::string> Record::route_to_stl(const sip_route_s *route) {
	std::list<std::string> res;
	SofiaAutoHome home;
	while (route != NULL) {
		res.push_back(std::string(url_as_string(home.home(), route->r_url)));
		route = route->r_next;
	}
	return res;
}

string Record::defineKeyFromUrl(const url_t *url) {
	ostringstream ostr;
	if (url->url_user) {
		if (!RegistrarDb::get()->useGlobalDomain()) {
			ostr<<url->url_user<<"@"<<url->url_host;
		} else {
			ostr<<url->url_user<<"@"<<"merged";
		}
	} else {
		ostr<<url->url_host;
	}
	return ostr.str();
}

void Record::insertOrUpdateBinding(const shared_ptr<ExtendedContact> &ec, const std::shared_ptr<ContactUpdateListener> &listener) {
	time_t now = ec->mUpdatedTime;

	SLOGD << "Trying to insert new contact " << *ec;

	if (sAssumeUniqueDomains && mIsDomain){
		mContacts.clear();
	}
	for (auto it = mContacts.begin(); it != mContacts.end();) {
		if (now >= (*it)->mExpireAt) {
			SLOGD << "Cleaning expired contact " << (*it)->mContactId;
			it = mContacts.erase(it);
		} else if (!(*it)->mUniqueId.empty() && (*it)->mUniqueId == ec->mUniqueId) {
			if (ec->mExpireAt == now){
				/*case of ;expires=0 in contact header*/
				if ((*it)->mUpdatedTime == now){
					/*this happens when a client (like Linphone) sends this kind of very ambiguous Contact header in a REGISTER
					 * Contact: <sip:marie_-jSau@ip1:39936;transport=tcp>;+sip.instance="<urn:uuid:bfb7514b-f793-4d85-b322-232044dc3731>"
					 * Contact: <sip:marie_-jSau@ip1:39934;transport=tcp>;+sip.instance="<urn:uuid:bfb7514b-f793-4d85-b322-232044dc3731>";expires=0
					 *
					 * We don't want the second line to unregister the first one, so don't touch anything*/
					return;
				}else{
					/*this contact should be removed*/
					it = mContacts.erase(it);
					return;
				}
			}
			SLOGD << "Cleaning older line '" << ec->mUniqueId << "' for contact " << (*it)->mContactId;
			ec->transferRegId((*it));
			if (listener) listener->onContactUpdated(*it);
			it = mContacts.erase(it);
		} else if ((*it)->mUniqueId.empty() && (*it)->callId() && (*it)->mCallId == ec->mCallId) {
			/*we don't accept to clean a contact from call-id if the unique id was set previously*/
			SLOGD << "Cleaning same call id contact " << (*it)->mContactId << "(" << ec->mCallId << ")";
			ec->transferRegId((*it));
			if (listener) listener->onContactUpdated(*it);
			it = mContacts.erase(it);
		} else {
			++it;
		}
	}
	mContacts.push_back(ec);
}

static bool compare_contact_using_last_update (shared_ptr<ExtendedContact> first, shared_ptr<ExtendedContact> second) {
	return first->mUpdatedTime < second->mUpdatedTime;
}

void Record::applyMaxAor() {
	// If contact doesn't exist and there is space left
	if (mContacts.size() > (unsigned int)sMaxContacts) {
		mContacts.sort(compare_contact_using_last_update);
		do {
			shared_ptr<ExtendedContact> front = mContacts.front();
			mContacts.pop_front();
			mContactsToRemove.push_back(front);
		} while (mContacts.size() > (unsigned int)sMaxContacts);
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

void ExtendedContact::setupRegid() {
	char strRegid[32] = {0};
	if (url_param(mSipContact->m_url->url_params, "regid", strRegid, sizeof(strRegid) - 1) > 0) {
		mRegId = std::strtoull(strRegid, NULL, 16);
	} else {
		ostringstream os;
		mRegId = su_random64();
		os << "regid=" << hex << mRegId;
		url_param_add(mHome.home(), mSipContact->m_url, os.str().c_str());
	}
}

string ExtendedContact::serializeAsUrlEncodedParams() {
	SofiaAutoHome home;
	sip_contact_t *contact = sip_contact_dup(home.home(), mSipContact);

	// CallId
	ostringstream oss;
	oss << "callid=" << mCallId;
	url_param_add(home.home(), contact->m_url, oss.str().c_str());

	// Q
	/*if (mQ == 0.f) {
		oss.str("");
		oss.clear();
		oss << "q=" << mQ;
		url_param_add(home.home(), contact->m_url, oss.str().c_str());
	}*/

	// Expire
	oss.str("");
	oss.clear();
	time_t expire = mExpireAt - getCurrentTime();
	oss << "expires=" << expire;
	url_param_add(home.home(), contact->m_url, oss.str().c_str());

	// CSeq
	oss.str("");
	oss.clear();
	oss << "cseq=" << mCSeq;
	url_param_add(home.home(), contact->m_url, oss.str().c_str());

	// Updated at
	oss.str("");
	oss.clear();
	oss << "updatedAt=" << mUpdatedTime;
	url_param_add(home.home(), contact->m_url, oss.str().c_str());

	// Alias
	oss.str("");
	oss.clear();
	oss << "alias=" << (mAlias ? "yes" : "no");
	url_param_add(home.home(), contact->m_url, oss.str().c_str());

	// Used as route
	oss.str("");
	oss.clear();
	oss << "usedAsRoute=" << (mUsedAsRoute ? "yes" : "no");
	url_param_add(home.home(), contact->m_url, oss.str().c_str());

	// Path
	ostringstream oss_path;
	for (auto it = mPath.begin(); it != mPath.end(); ++it) {
		if (it != mPath.begin()) oss_path << ",";
		oss_path << *it;
	}

	// AcceptHeaders
	ostringstream oss_accept;
	for (auto it = mAcceptHeader.begin(); it != mAcceptHeader.end(); ++it) {
		if (it != mAcceptHeader.begin()) oss_accept << ",";
		oss_accept << *it;
	}

	contact->m_url->url_headers = sip_headers_as_url_query(home.home(),
		SIPTAG_PATH_STR(oss_path.str().c_str()), SIPTAG_ACCEPT_STR(oss_accept.str().c_str()),
		TAG_END());

	string contact_string(sip_header_as_string(home.home(), (sip_header_t const *)contact));
	return contact_string;
}

static string getStringParam(url_t *url, const char *param) {
	string extracted_param;
	if (url_has_param(url, param)) {
		char *buffer = new char[255];
		isize_t result = url_param(url->url_params, param, buffer, 255);
		if (result > 0) {
			extracted_param = string(buffer);
		}
		url->url_params = url_strip_param_string((char *)url->url_params, param);
		delete[] buffer;
	}
	return extracted_param;
}

static int getIntParam(url_t *url, const char *param) {
	int extracted_param = 0;
	if (url_has_param(url, param)) {
		char *buffer = new char[255];
		isize_t result = url_param(url->url_params, param, buffer, 255);
		if (result > 0) {
			extracted_param = atoi(buffer);
		}
		url->url_params = url_strip_param_string((char *)url->url_params, param);
		delete[] buffer;
	}
	return extracted_param;
}

static int getUnsignedLongParam(url_t *url, const char *param) {
	unsigned long extracted_param = 0;
	if (url_has_param(url, param)) {
		char *buffer = new char[255];
		isize_t result = url_param(url->url_params, param, buffer, 255);
		if (result > 0) {
			extracted_param = (unsigned long) atoll(buffer);
		}
		url->url_params = url_strip_param_string((char *)url->url_params, param);
		delete[] buffer;
	}
	return extracted_param;
}

static bool getBoolParam(url_t *url, const char *param) {
	bool extracted_param = false;
	if (url_has_param(url, param)) {
		char *buffer = new char[255];
		isize_t result = url_param(url->url_params, param, buffer, 255);
		if (result > 0) {
			extracted_param = strcmp(buffer, "yes") == 0;
		}
		url->url_params = url_strip_param_string((char *)url->url_params, param);
		delete[] buffer;
	}
	return extracted_param;
}

bool Record::updateFromUrlEncodedParams(const char *key, const char *uid, const char *full_url) {
	bool result = false;
	SofiaAutoHome home;

	sip_contact_t *temp_contact = sip_contact_make(home.home(), full_url);
	url_t *url = NULL;
	if (temp_contact == NULL) {
		SLOGD << "Couldn't parse " << full_url << " as contact, fallback to url instead";
		url = url_make(home.home(), full_url);
	} else {
		url = temp_contact->m_url;
	}

	// CallId
	string call_id = getStringParam(url, "callid");

	// Expire
	int globalExpire = getIntParam(url, "expires");

	// Update time
	unsigned long updatedAt = getUnsignedLongParam(url, "updatedAt");

	// CSeq
	uint32_t cseq = getIntParam(url, "cseq");

	// Alias
	bool alias = getBoolParam(url, "alias");

	// Used as route
	bool usedAsRoute = getBoolParam(url, "usedAsRoute");

	// Path
	list<string> path;
	// Accept headers
	list<string> acceptHeaders;

	char *headers = url_query_as_header_string(home.home(), url->url_headers);
	char *line = NULL;
	while ((line = strsep(&headers, "\n")) != NULL)
	{
		char *ptr;
		strtok_r(line, ":", &ptr);
		if (line) {
			if (strcmp(line, "path") == 0 && ptr) {
				char *item = NULL;
				while ((item = strsep(&ptr, ",")) != NULL) {
					path.push_back(item);
				}
			} else if (strcmp(line, "accept") == 0 && ptr) {
				char *item = NULL;
				while ((item = strsep(&ptr, ",")) != NULL) {
					acceptHeaders.push_back(item);
				}
			}
		}
	}

	char transport[20] = {0};
	url_param(url[0].url_params, "transport", transport, sizeof(transport) - 1);

	url->url_headers = NULL;
	sip_contact_t *contact = NULL;
	if (temp_contact == NULL)
		contact = sip_contact_create(home.home(), (url_string_t*)url, NULL);
	else
		contact = temp_contact;

	if (contact == NULL) {
		return result;
	}

	ExtendedContactCommon ecc(key, path, call_id, uid);
	auto exc = make_shared<ExtendedContact>(ecc, contact, globalExpire, cseq, updatedAt, alias, acceptHeaders);
	exc->setupRegid();
	exc->mUsedAsRoute = usedAsRoute;

	if (getCurrentTime() < exc->mExpireAt) {
		insertOrUpdateBinding(exc, nullptr);
		result = true;
	}

	return result;
}

void Record::update(sip_contact_t *contacts, const sip_path_t *path, int globalExpire, const std::string &call_id,
					uint32_t cseq, time_t now, bool alias, const std::list<std::string> accept, bool usedAsRoute,
					const std::shared_ptr<ContactUpdateListener> &listener) {
	list<string> stlPath;

	if (path != NULL) {
		stlPath = route_to_stl(path);
	}

	while (contacts) {
		const char *lineValuePtr = NULL;
		string lineValue = extractUniqueId(contacts);
		if (!lineValue.empty())
			lineValuePtr = lineValue.c_str();

		char transport[20];
		char *transportPtr = transport;
		if (!url_param(contacts->m_url[0].url_params, "transport", transport, sizeof(transport) - 1)) {
			transportPtr = NULL;
		}

		ostringstream contactId;
		defineContactId(contactId, contacts->m_url, transportPtr);
		ExtendedContactCommon ecc(contactId.str().c_str(), stlPath, call_id, lineValuePtr);
		auto exc = make_shared<ExtendedContact>(ecc, contacts, globalExpire, cseq, now, alias, accept);
		exc->setupRegid();
		exc->mUsedAsRoute = usedAsRoute;
		insertOrUpdateBinding(exc, listener);
		contacts = contacts->m_next;
	}
	applyMaxAor();

	SLOGD << *this;
}

void Record::update(const ExtendedContactCommon &ecc, const char *sipuri, long expireAt, float q, uint32_t cseq,
					time_t updated_time, bool alias, const std::list<std::string> accept, bool usedAsRoute,
					const std::shared_ptr<ContactUpdateListener> &listener) {
	SofiaAutoHome home;
	url_t *sipUri = url_make(home.home(), sipuri);
	if (!sipUri){
		LOGE("Record::update(): could not build sip uri.");
		return;
	}
	sip_contact_t *contact = sip_contact_create(home.home(), (url_string_t*)sipUri, NULL);
	if (!contact){
		LOGE("Record::update(): could not build contact.");
		return;
	}
	auto exct = make_shared<ExtendedContact>(ecc, contact, expireAt, cseq, updated_time, alias, accept);
	exct->setupRegid();
	exct->mUsedAsRoute = usedAsRoute;
	insertOrUpdateBinding(exct, listener);
	applyMaxAor();

	SLOGD << *this;
}

void Record::print(std::ostream &stream) const {
	stream << "Record contains " << mContacts.size() << " contacts";
	time_t now = getCurrentTime();
	time_t offset = getTimeOffset(now);

	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		stream << "\n";
		(*it)->print(stream, now, offset);
	}
	stream << "\n==========================";
}

int Record::sMaxContacts = -1;
list<string> Record::sLineFieldNames;
bool Record::sAssumeUniqueDomains = false;

Record::Record(const url_t *aor) : mKey(aor ? defineKeyFromUrl(aor) : "") {
	if (sMaxContacts == -1)
		init();
	if (aor) mIsDomain = aor->url_user == NULL;
}

Record::~Record() {
}

void Record::init() {
	GenericStruct *registrar = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	sMaxContacts = registrar->get<ConfigInt>("max-contacts-by-aor")->read();
	sLineFieldNames = registrar->get<ConfigStringList>("unique-id-parameters")->read();
	sAssumeUniqueDomains = GenericManager::get()
								   ->getRoot()
								   ->get<GenericStruct>("inter-domain-connections")
								   ->get<ConfigBoolean>("assume-unique-domains")
								   ->read();
}

void Record::appendContactsFrom(Record *src) {
	if (!src)
		return;

	for (auto it = src->mContacts.begin(); it != src->mContacts.end(); ++it) {
		mContacts.push_back(*it);
	}
}

RegistrarDb::LocalRegExpire::LocalRegExpire(string preferredRoute) {
	mPreferedRoute = preferredRoute;
}

RegistrarDb::RegistrarDb(const string &preferredRoute)
	: mLocalRegExpire(new LocalRegExpire(preferredRoute)), mUseGlobalDomain(false) {
}

RegistrarDb::~RegistrarDb() {
	delete mLocalRegExpire;
}

void RegistrarDb::subscribe(const std::string &topic, const std::shared_ptr<ContactRegisteredListener> &listener) {
	LOGD("Subscribe topic = %s", topic.c_str());
	mContactListenersMap.insert(make_pair(topic, listener));
}

void RegistrarDb::unsubscribe(const std::string &topic) {
	LOGD("Unsubscribe topic = %s", topic.c_str());
	auto it = mContactListenersMap.find(topic);
	if (it != mContactListenersMap.end()) {
		mContactListenersMap.erase(topic);
	}
}

void RegistrarDb::notifyContactListener(const std::string &key, const std::string &uid) {
	LOGD("Notify topic = %s, uid = %s", key.c_str(), uid.c_str());
	auto it = mContactListenersMap.find(key);
	if (it != mContactListenersMap.end()) {
		std::shared_ptr<ContactRegisteredListener> listener = (*it).second;
		listener->onContactRegistered(key, uid);
	}
}

void RegistrarDb::LocalRegExpire::update(const Record &record) {
	unique_lock<mutex> lock(mMutex);
	time_t latest = record.latestExpire(mPreferedRoute);
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

	for (auto it = mRegMap.begin(); it != mRegMap.end();) {
		// LOGE("> %s [%lu]", (*it).first.c_str(), (*it).second-before);
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
	sip_contact_t *current = (sip_contact_t *)contact;
	while (current) {
		if (!current->m_expires || atoi(current->m_expires) != 0){
			++count;
		}
		current = current->m_next;
	}
	return count;
}

bool RegistrarDb::errorOnTooMuchContactInBind(const sip_contact_t *sip_contact, const string & key,
											  const shared_ptr<RegistrarDbListener> &listener) {
	int nb_contact = count_sip_contacts(sip_contact);
	int max_contact = Record::getMaxContacts();
	if (nb_contact > max_contact) {
		LOGD("Too many contacts in register %s %i > %i", key.c_str(), nb_contact,
			 max_contact);
		return true;
	}

	return false;
}

RegistrarDb *RegistrarDb::sUnique = NULL;

RegistrarDb *RegistrarDb::initialize(Agent *ag){
	if (sUnique != NULL){
		LOGF("RegistrarDb already initialized");
	}
	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *mr = cr->get<GenericStruct>("module::Registrar");
	GenericStruct *mro = cr->get<GenericStruct>("module::Router");

	bool useGlobalDomain = mro->get<ConfigBoolean>("use-global-domain")->read();
	string dbImplementation = mr->get<ConfigString>("db-implementation")->read();
	string mMessageExpiresName = mr->get<ConfigString>("name-message-expires")->read();
	if ("internal" == dbImplementation) {
		LOGI("RegistrarDB implementation is internal");
		sUnique = new RegistrarDbInternal(ag->getPreferredRoute());
		sUnique->mUseGlobalDomain = useGlobalDomain;
	}
#ifdef ENABLE_REDIS
	/* Previous implementations allowed "redis-sync" and "redis-async", whereas we now expect "redis".
		* We check that the dbImplementation _starts_ with "redis" now, so that we stay backward compatible. */
	else if (dbImplementation.find("redis") == 0) {
		LOGI("RegistrarDB implementation is REDIS");
		GenericStruct *registrar = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
		RedisParameters params;
		params.domain = registrar->get<ConfigString>("redis-server-domain")->read();
		params.port = registrar->get<ConfigInt>("redis-server-port")->read();
		params.timeout = registrar->get<ConfigInt>("redis-server-timeout")->read();
		params.auth = registrar->get<ConfigString>("redis-auth-password")->read();
		params.mSlaveCheckTimeout = registrar->get<ConfigInt>("redis-slave-check-period")->read();

		sUnique = new RegistrarDbRedisAsync(ag, params);
		sUnique->mUseGlobalDomain = useGlobalDomain;
	}
#endif
	else {
		LOGF("Unsupported implementation '%s'. %s",
#ifdef ENABLE_REDIS
				"Supported implementations are 'internal' or 'redis'.", dbImplementation.c_str());
#else
				"Supported implementation is 'internal'.", dbImplementation.c_str());
#endif
	}
	sUnique->mMessageExpiresName = mMessageExpiresName;
	return sUnique;
}

RegistrarDb *RegistrarDb::get() {
	if (sUnique == NULL) {
		LOGF("RegistrarDb not initialized.");
	}
	return sUnique;
}

void RegistrarDb::clear(const sip_t *sip, const shared_ptr<ContactUpdateListener> &listener) {
	doClear(sip, listener);
}

class RecursiveRegistrarDbListener : public ContactUpdateListener,
									 public enable_shared_from_this<RecursiveRegistrarDbListener> {
  private:
	RegistrarDb *m_database;
	shared_ptr<ContactUpdateListener> mOriginalListener;
	Record *m_record;
	su_home_t m_home;
	int m_request;
	int m_step;
	const char *m_url;
	static int sMaxStep;

  public:
	RecursiveRegistrarDbListener(RegistrarDb *database, const shared_ptr<ContactUpdateListener> &original_listerner,
								 const url_t *url, int step = sMaxStep)
		: m_database(database), mOriginalListener(original_listerner), m_request(1), m_step(step) {
		m_record = new Record(url);
		su_home_init(&m_home);
		m_url = url_as_string(&m_home, url);
	}

	~RecursiveRegistrarDbListener() {
		su_home_deinit(&m_home);
		delete m_record;
	}

	void onRecordFound(Record *r) {
		if (r != NULL) {
			auto &extlist = r->getExtendedContacts();
			list<sip_contact_t *> vectToRecurseOn;
			for (auto it : extlist) {
				shared_ptr<ExtendedContact> ec = it;
				// Also add alias for late forking (context in the forks map for this alias key)
				SLOGD << "Step: " << m_step << (ec->mAlias ? "\tFound alias " : "\tFound contact ") << m_url << " -> "
					  << ExtendedContact::urlToString(ec->mSipContact->m_url) << " usedAsRoute:" << ec->mUsedAsRoute;
				if (!ec->mAlias && ec->mUsedAsRoute) {
					ec = transformContactUsedAsRoute(m_url, ec);
				}
				m_record->pushContact(ec);
				if (ec->mAlias && m_step > 0) {
					sip_contact_t *contact = sip_contact_create(&m_home, (url_string_t*)ec->mSipContact->m_url, NULL);
					if (contact) {
						vectToRecurseOn.push_back(contact);
					} else {
						SLOGW << "Can't create sip_contact of " << ExtendedContact::urlToString(ec->mSipContact->m_url);
					}
				}
			}
			m_request += vectToRecurseOn.size();
			for (auto itrec : vectToRecurseOn) {
				m_database->fetch(itrec->m_url,
								  make_shared<RecursiveRegistrarDbListener>(m_database, this->shared_from_this(),
																			itrec->m_url, m_step - 1),
								  false);
			}
		}

		if (waitPullUpOrFail()) {
			SLOGD << "Step: " << m_step << "\tNo contact found for " << m_url;
			mOriginalListener->onRecordFound(NULL);
		}
	}

	void onError() {
		SLOGW << "Step: " << m_step << "\tError during recursive fetch of " << m_url;
		if (waitPullUpOrFail()) {
			mOriginalListener->onError();
		}
	}

	void onInvalid() {
		SLOGW << "Step: " << m_step << "\tInvalid during recursive fetch of " << m_url;
		if (waitPullUpOrFail()) {
			mOriginalListener->onInvalid();
		}
	}

	void onContactUpdated(const shared_ptr<ExtendedContact> &ec) {
	}

  private:
	shared_ptr<ExtendedContact> transformContactUsedAsRoute(const char *uri, const shared_ptr<ExtendedContact> &ec) {
		/* This function does the following:
		 * - make a copy of the extended contact
		 * - in this copy replace the main contact information by the 'uri' given in argument
		 * - append the main contact information of the original extended contact into the Path header of the new
		 * extended contact.
		 * While recursiving through alias, this allows to have a Route header appended for a "usedAsRoute" kind of
		 * Contact but still preserving
		 * the last request uri that was found recursed through the alias mechanism.
		*/
		shared_ptr<ExtendedContact> newEc = make_shared<ExtendedContact>(*ec);
		newEc->mSipContact = sip_contact_create(newEc->mHome.home(), (url_string_t*)uri, NULL);
		ostringstream path;
		path<<*ec->toSofiaUrlClean(newEc->mHome.home());
		newEc->mPath.push_back(path.str());
		// LOGD("transformContactUsedAsRoute(): path to %s added for %s", ec->mSipUri.c_str(), uri);
		newEc->mUsedAsRoute = false;
		return newEc;
	}

	bool waitPullUpOrFail() {
		if (--m_request != 0)
			return false; // wait for all pending responses

		// No more results expected for this recursion level
		if (m_record->getExtendedContacts().empty()) {
			return true; // no contacts collected on below recursion levels
		}

		// returning records collected on below recursion levels
		SLOGD << "Step: " << m_step << "\tReturning collected records " << m_record->getExtendedContacts().size();
		mOriginalListener->onRecordFound(m_record);
		return false;
	}
};

// Max recursive step
int RecursiveRegistrarDbListener::sMaxStep = 1;

RegistrarDbListener::~RegistrarDbListener() {
}

ContactUpdateListener::~ContactUpdateListener() {
}

ContactRegisteredListener::~ContactRegisteredListener() {
}

void RegistrarDb::fetch(const url_t *url, const shared_ptr<ContactUpdateListener> &listener, bool recursive) {
	fetch(url, listener, false, recursive);
}

void RegistrarDb::fetch(const url_t *url, const std::shared_ptr<ContactUpdateListener> &listener, bool includingDomains, bool recursive) {
	if (includingDomains) {
		fetchWithDomain(url, listener, recursive);
		return;
	}
	if(url_has_param(url, "gr")) {
		stringstream gruu;
		char *buffer = new char[255];
		isize_t result = url_param(url->url_params, "gr", buffer, 255);
		if (result > 0) {
			gruu << "\"<" << buffer << ">\"";
			doFetchForGruu(url, gruu.str(), recursive
						   ? make_shared<RecursiveRegistrarDbListener>(this, listener, url)
						   : listener);
			return;
		}
	}
	doFetch(url, recursive
			? make_shared<RecursiveRegistrarDbListener>(this, listener, url)
			: listener);
}

void RegistrarDb::fetchForGruu(const url_t *url, const std::string &gruu, const std::shared_ptr<ContactUpdateListener> &listener) {
	doFetchForGruu(url, gruu, listener);
}

void RegistrarDb::bind(const url_t *ifrom, sip_contact_t *icontact, const char *iid, uint32_t iseq,
					  const sip_path_t *ipath, const sip_supported_t *isupported, const sip_accept_t *iaccept, bool usedAsRoute, int expire,
					  bool alias, int version, const std::shared_ptr<ContactUpdateListener> &listener)
{
	SofiaAutoHome home;
	const sip_accept_t *accept = iaccept;
	list<string> acceptHeaders;
	while (accept != NULL) {
		acceptHeaders.push_back(accept->ac_type);
		accept = accept->ac_next;
	}

	// FIXME : get supported as header not string...
	if (isupported && icontact->m_params) {
		string supported(sip_header_as_string(home.home(), (sip_header_t *) isupported));
		if (supported.find("gruu") != string::npos) {
			stringstream stream;
			const char *token = "+sip.instance";
			const char *instance_param = msg_params_find(icontact->m_params, token);
			string instance(instance_param);
			if (instance.find("\"<") != string::npos) {
				instance = instance.substr(instance.find("\"<") + strlen("\"<"));
				instance = instance.substr(0, instance.find(">"));
				stream << "gr=" << instance;
				url_param_add(home.home(), icontact->m_url, stream.str().c_str());
			}
		}
	}

	int countSipContacts = count_sip_contacts(icontact);
	if (countSipContacts > Record::getMaxContacts()) {
		LOGD("Too many contacts in register %s %i > %i", Record::defineKeyFromUrl(ifrom).c_str(), countSipContacts, Record::getMaxContacts());
		listener->onError();
		return;
	}

	doBind(ifrom, icontact, iid, iseq, ipath, acceptHeaders, usedAsRoute, expire, alias, version, listener);
}
void RegistrarDb::bind(const sip_t *sip, int globalExpire, bool alias, int version, const std::shared_ptr<ContactUpdateListener> &listener) {
	bind(sip->sip_from->a_url, sip->sip_contact, sip->sip_call_id->i_id, sip->sip_cseq->cs_seq,
		sip->sip_path, sip->sip_supported, sip->sip_accept, sip->sip_from->a_url->url_user == NULL,
		globalExpire, alias, version, listener);
}

class AgregatorRegistrarDbListener : public ContactUpdateListener {
  private:
	shared_ptr<ContactUpdateListener> mOriginalListener;
	int mNumRespExpected;
	int mNumResponseObtained;
	Record *mRecord;
	bool mError;
	Record *getRecord() {
		if (mRecord == NULL)
			mRecord = new Record(NULL);
		return mRecord;
	}
	void checkFinished() {
		mNumResponseObtained++;
		if (mNumResponseObtained == mNumRespExpected) {
			if (mError && mRecord == NULL) {
				mOriginalListener->onError();
			} else {
				mOriginalListener->onRecordFound(mRecord);
			}
		}
	}

  public:
	AgregatorRegistrarDbListener(const shared_ptr<ContactUpdateListener> &origListener, int numResponseExpected)
		: mOriginalListener(origListener), mNumRespExpected(numResponseExpected), mNumResponseObtained(0), mRecord(0) {
		mError = false;
	}
	virtual ~AgregatorRegistrarDbListener() {
		if (mRecord)
			delete mRecord;
	}
	virtual void onRecordFound(Record *r) {
		if (r) {
			getRecord()->appendContactsFrom(r);
		}
		checkFinished();
	}
	virtual void onError() {
		mError = true;
		checkFinished();
	}
	virtual void onInvalid() {
		// onInvalid() will normally never be called for a fetch request
		checkFinished();
	}

	virtual void onContactUpdated(const shared_ptr<ExtendedContact> &ec) {
	}
};

void RegistrarDb::fetchWithDomain(const url_t *url, const std::shared_ptr<ContactUpdateListener> &listener,
								  bool recursive) {
	url_t domainOnlyUrl = *url;
	domainOnlyUrl.url_user = NULL;

	auto agregator = make_shared<AgregatorRegistrarDbListener>(listener, 2);
	fetch(url, agregator, recursive);
	fetch(&domainOnlyUrl, agregator, false);
}

RecordSerializer *RecordSerializer::create(const string &name) {
	if (name == "c") {
		return new RecordSerializerC();
	} else if (name == "json") {
		return new RecordSerializerJson();
	}
#if ENABLE_PROTOBUF
	else if (name == "protobuf") {
		return new RecordSerializerPb();
	}
#endif
#if ENABLE_MSGPACK
	else if (name == "msgpack"){
		return new RecordSerializerMsgPack();
	}
#endif
	else {
		return NULL;
	}
}

RecordSerializer *RecordSerializer::sInstance = NULL;

RecordSerializer *RecordSerializer::get() {
	if (!sInstance) {
		GenericStruct *registrar = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
		string name = registrar->get<ConfigString>("redis-record-serializer")->read();

		sInstance = create(name);
		if (!sInstance) {
			LOGW("Unsupported record serializer: '%s'", name.c_str());
		}
	}

	return sInstance;
}
