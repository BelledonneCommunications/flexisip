/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <ostream>
#include <sstream>

#include <sofia-sip/sip_protos.h>

#include <flexisip/common.hh>
#include <flexisip/configmanager.hh>
#include <flexisip/module.hh>

#include "recordserializer.hh"
#include "registrardb-internal.hh"
#include "registrardb.hh"
#ifdef ENABLE_REDIS
#include "registrardb-redis.hh"
#endif
#include "utils/string-utils.hh"
#include "utils/uri-utils.hh"

using namespace std;
using namespace flexisip;

ostream& ExtendedContact::print(ostream& stream, time_t _now, time_t _offset) const {
	time_t now = _now;
	time_t offset = _offset;
	char buffer[256] = "UNDETERMINED";
	time_t expire = mExpireAt;
	expire += offset;
	struct tm* ptm = localtime(&expire);
	if (ptm != nullptr) {
		strftime(buffer, sizeof(buffer) - 1, "%c", ptm);
	}
	long expireAfter = mExpireNotAtMessage - now;

	stream << urlToString(mSipContact->m_url) << " path=\"";
	for (auto it = mPath.cbegin(); it != mPath.cend(); ++it) {
		if (it != mPath.cbegin()) stream << " ";
		stream << *it;
	}
	stream << "\"";
	stream << " user-agent=\"" << mUserAgent << "\"";
	stream << " alias=" << (mAlias ? "yes" : "no");
	if (!mAlias) stream << " uid=" << mUniqueId;
	stream << " expire=" << expireAfter << " s (" << buffer << ")";
	return stream;
}

url_t* ExtendedContact::toSofiaUrlClean(su_home_t* home) {
	url_t* ret = nullptr;
	if (!mSipContact) return nullptr;

	ret = url_hdup(home, mSipContact->m_url);
	ret->url_params = url_strip_param_string((char*)ret->url_params, "fs-conn-id");
	return ret;
}

string ExtendedContact::getOrgLinphoneSpecs() const {
	if (!mSipContact) return string();
	const char* specs = msg_params_find(mSipContact->m_params, "+org.linphone.specs");
	string result = specs ? string(specs) : string();
	return result;
}

const string ExtendedContact::getMessageExpires(const msg_param_t* m_params) {
	return RegistrarDb::get()->getMessageExpires(m_params);
}

sip_contact_t* ExtendedContact::toSofiaContact(su_home_t* home) const {
	mSipContact->m_next = nullptr;
	return sip_contact_dup(home, mSipContact);
}

sip_route_t* ExtendedContact::toSofiaRoute(su_home_t* home) const {
	sip_route_t* rbegin = nullptr;
	sip_route_t* r = nullptr;
	for (auto it = mPath.begin(); it != mPath.end(); ++it) {
		sip_route_t* newr = sip_route_format(home, "<%s>", (*it).c_str());
		if (!newr) {
			LOGE("Cannot parse %s into route header", (*it).c_str());
			break;
		}
		if (!url_has_param(newr->r_url, "lr")) {
			url_param_add(home, newr->r_url, "lr");
		}
		if (rbegin == nullptr) {
			rbegin = newr;
		} else {
			r->r_next = newr;
		}
		r = newr;
	}
	return rbegin;
}

sip_contact_t* Record::getContacts(su_home_t* home, time_t now) {
	sip_contact_t* alist = nullptr;
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		if ((*it)->isExpired(now)) {
			continue;
		}

		sip_contact_t* current = (*it)->toSofiaContact(home);
		if (alist) {
			current->m_next = alist;
		}
		alist = current;
	}
	return alist;
}

bool Record::isInvalidRegister(const string& call_id, uint32_t cseq) {
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		shared_ptr<ExtendedContact> ec = (*it);
		if ((0 == strcmp(ec->callId(), call_id.c_str())) && cseq <= ec->mCSeq) {
			LOGD("CallID %s already registered with CSeq %d (received %d)", call_id.c_str(), ec->mCSeq, cseq);
			return true;
		}
	}
	return false;
}

string Record::extractUniqueId(const sip_contact_t* contact) {
	char lineValue[256] = {0};

	/*search for device unique parameter among the ones configured */
	for (auto it = sLineFieldNames.begin(); it != sLineFieldNames.end(); ++it) {
		const char* ct_param = msg_params_find(contact->m_params, it->c_str());
		if (ct_param) return ct_param;
		if (url_param(contact->m_url->url_params, it->c_str(), lineValue, sizeof(lineValue) - 1) > 0) {
			return lineValue;
		}
	}

	return "";
}

const shared_ptr<ExtendedContact> Record::extractContactByUniqueId(const string& uid) const {
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

/**
 * Should first have checked the validity of the register with isValidRegister.
 */
void Record::clean(time_t now, const shared_ptr<ContactUpdateListener>& listener) {
	auto it = mContacts.begin();
	while (it != mContacts.end()) {
		shared_ptr<ExtendedContact> ec = (*it);
		if (now >= ec->mExpireAt) {
			if (listener) listener->onContactUpdated(ec);
			it = mContacts.erase(it);
		} else {
			++it;
		}
	}
}

time_t Record::latestExpire() const {
	time_t latest = 0;
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		if ((*it)->mExpireAt > latest) latest = (*it)->mExpireAt;
	}
	return latest;
}

time_t Record::latestExpire(Agent* ag) const {
	time_t latest = 0;
	sofiasip::Home home;

	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		if ((*it)->mPath.empty() || (*it)->mExpireAt <= latest) continue;

		/* Remove extra parameters */
		string s = *(*it)->mPath.begin();
		string::size_type n = s.find(";");
		if (n != string::npos) s = s.substr(0, n);
		url_t* url = url_make(home.home(), s.c_str());

		if (ag->isUs(url)) latest = (*it)->mExpireAt;
	}
	return latest;
}

list<string> Record::route_to_stl(const sip_route_s* route) {
	list<string> res;
	sofiasip::Home home;
	while (route != nullptr) {
		res.push_back(string(url_as_string(home.home(), route->r_url)));
		route = route->r_next;
	}
	return res;
}

string Record::defineKeyFromUrl(const url_t* url) {
	ostringstream ostr;
	if (url == nullptr) return string{};
	const char* user = url->url_user;
	if (user && user[0] != '\0') {
		if (!RegistrarDb::get()->useGlobalDomain()) {
			ostr << user << "@" << url->url_host;
		} else {
			ostr << user << "@"
			     << "merged";
		}
	} else {
		ostr << url->url_host;
	}
	return ostr.str();
}

SipUri Record::makeUrlFromKey(const string& key) {
	return SipUri("sip:" + key);
}

void Record::insertOrUpdateBinding(const shared_ptr<ExtendedContact>& ec,
                                   const shared_ptr<ContactUpdateListener>& listener) {
	time_t now = time(NULL);
	bool matched = false;

	SLOGD << "Updating record with contact " << *ec;

	if (sAssumeUniqueDomains && mIsDomain) {
		for (auto& ct : mContacts)
			mContactsToRemove.push_back(ct);
		mContacts.clear();
	}
	for (auto it = mContacts.begin(); it != mContacts.end();) {
		if (!(*it)->mUniqueId.empty() && (*it)->mUniqueId == ec->mUniqueId) {
			matched = true;
			if (ec->isExpired(now)) {
				SLOGD << "Contact removed based on unique id";
				mContactsToRemove.push_back(*it);
			} else {
				SLOGD << "Contact updated based on unique id";
			}
			if (listener) listener->onContactUpdated(*it);
			it = mContacts.erase(it);
		} else if ((*it)->mUniqueId.empty() && (*it)->callId() && (*it)->mCallId == ec->mCallId) {
			matched = true;
			if (ec->isExpired(now)) {
				SLOGD << "Contact removed based on Call-ID";
				mContactsToRemove.push_back(*it);
			} else {
				SLOGD << "Contact updated based on Call-ID";
			}
			if (listener) listener->onContactUpdated(*it);
			it = mContacts.erase(it);
		} else if ((*it)->mPushParamList == ec->mPushParamList) {
			if ((*it)->mUpdatedTime < ec->mUpdatedTime) {
				matched = true;
				SLOGD << "Removing contact [" << (*it)->contactId() << "] with push param in common : new["
				      << ec->mPushParamList << "], actual[" << (*it)->mPushParamList << "]";
				mContactsToRemove.push_back(*it);
				it = mContacts.erase(it);
			} else {
				SLOGW << "Inserted contact has same push parameters of another more recent contact, this should not "
				         "happen.";
				++it;
			}
		} else if (ec->isExpired(now) && url_cmp_all(ec->mSipContact->m_url, (*it)->mSipContact->m_url) == 0) {
			/*case of ;expires=0 in contact header. Try to match the uri content directly.*/
			SLOGD << "Contact removed based on uri match.";
			matched = true;
			mContactsToRemove.push_back(*it);
			it = mContacts.erase(it);
		} else if (now >= (*it)->mExpireAt) {
			SLOGD << "Cleaning expired contact '" << (*it)->contactId() << "'";
			mContactsToRemove.push_back(*it);
			it = mContacts.erase(it);
		} else {
			++it;
		}
	}
	/* Add the new contact, if not expired (ie with expires=0) */
	if (!ec->isExpired(now)) {
		mContacts.push_back(ec);
		mContactsToAddOrUpdate.push_back(ec);
	} else if (!matched) {
		SLOGD << "This contact is expired.";
		mContactsToRemove.push_back(ec);
	}

	if (ec->mCallId.find("static-record") == string::npos) {
		mOnlyStaticContacts = false;
	}
}

void ExtendedContact::extractInfoFromHeader(const char* urlHeaders) {
	if (urlHeaders) {
		sofiasip::Home home;
		msg_header_t* headers;
		char* stringHeaders = url_query_as_header_string(home.home(), urlHeaders);
		unique_ptr<msg_t, void (*)(msg_t*)> msg(msg_create(sip_default_mclass(), 0), msg_destroy);

		if (msg_header_parse_str(msg.get(), nullptr, stringHeaders) != 0) return;
		// We need to add a sip_request to validate msg_serialize() contidition
		if (msg_header_add_dup(
		        msg.get(), nullptr,
		        reinterpret_cast<msg_header_t*>(sip_request_make(home.home(), "MESSAGE sip:abcd SIP/2.0\r\n"))) != 0)
			return;
		if (msg_serialize(msg.get(), nullptr) != 0) return;
		msg_prepare(msg.get());

		headers = *msg_chain_head(msg.get());

		while (headers) {
			if (reinterpret_cast<msg_common_t*>(headers)->h_len > 0 &&
			    reinterpret_cast<msg_common_t*>(headers)->h_class->hc_name) {
				string valueStr;
				string keyStr = reinterpret_cast<msg_common_t*>(headers)->h_class->hc_name;

				valueStr.resize(reinterpret_cast<msg_common_t*>(headers)->h_len + 1);
				size_t written =
				    msg_header_field_e(&valueStr[0], reinterpret_cast<msg_common_t*>(headers)->h_len, headers, 0);
				valueStr.resize(written);

				transform(keyStr.begin(), keyStr.end(), keyStr.begin(),
				          [](unsigned char c) { return std::tolower(c); });

				if (keyStr == "path") {
					// We want to keep only the uri part of the paths.
					sip_path_t* path = sip_path_format(home.home(), "%s", valueStr.c_str());
					if (path) {
						mPath.push_back(url_as_string(home.home(), path->r_url));
					} else {
						LOGE("ExtendedContact::extractInfoFromHeader(): bad path [%s]", valueStr.c_str());
					}
				} else if (keyStr == "accept") {
					mAcceptHeader.push_back(valueStr);
				} else if (keyStr == "user-agent") {
					mUserAgent = valueStr;
				}
			}
			headers = reinterpret_cast<msg_common_t*>(headers)->h_succ;
		}
	}
}

utils::Utf8String ExtendedContact::getDeviceName() const {
	const string& userAgent = mUserAgent;
	size_t begin = userAgent.find("(");
	string deviceName;
	if (begin != string::npos) {
		size_t end = userAgent.find(")", begin);
		size_t openingParenthesis = userAgent.find("(", begin + 1);
		while (openingParenthesis != string::npos && openingParenthesis < end) {
			openingParenthesis = userAgent.find("(", openingParenthesis + 1);
			end = userAgent.find(")", end + 1);
		}
		if (end != string::npos) {
			deviceName = userAgent.substr(begin + 1, end - (begin + 1));
		}
	}
	return deviceName;
}

static bool compare_contact_using_last_update(shared_ptr<ExtendedContact> first, shared_ptr<ExtendedContact> second) {
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

string ExtendedContact::serializeAsUrlEncodedParams() {
	sofiasip::Home home;
	string param{};
	sip_contact_t* contact = sip_contact_dup(home.home(), mSipContact);

	// CallId
	param = "callid=" + UriUtils::escape(mCallId, UriUtils::sipUriParamValueReserved);
	url_param_add(home.home(), contact->m_url, param.c_str());

	// Expire
	auto expire = mExpireNotAtMessage - getCurrentTime();
	param = "expires=" + to_string(expire);
	url_param_add(home.home(), contact->m_url, param.c_str());

	// CSeq
	param = "cseq=" + to_string(mCSeq);
	url_param_add(home.home(), contact->m_url, param.c_str());

	// Updated at
	param = "updatedAt=" + to_string(mUpdatedTime);
	url_param_add(home.home(), contact->m_url, param.c_str());

	// Alias
	param = string{"alias="} + (mAlias ? "yes" : "no");
	url_param_add(home.home(), contact->m_url, param.c_str());

	// Used as route
	param = string{"usedAsRoute="} + (mUsedAsRoute ? "yes" : "no");
	url_param_add(home.home(), contact->m_url, param.c_str());

	// Path
	ostringstream oss_path{};
	for (auto it = mPath.cbegin(); it != mPath.cend(); ++it) {
		if (it != mPath.cbegin()) oss_path << ",";
		oss_path << "<" << *it << ">";
	}

	// AcceptHeaders
	ostringstream oss_accept{};
	for (auto it = mAcceptHeader.cbegin(); it != mAcceptHeader.cend(); ++it) {
		if (it != mAcceptHeader.cbegin()) oss_accept << ",";
		oss_accept << *it;
	}

	contact->m_url->url_headers = sip_headers_as_url_query(home.home(), SIPTAG_PATH_STR(oss_path.str().c_str()),
	                                                       SIPTAG_ACCEPT_STR(oss_accept.str().c_str()),
	                                                       SIPTAG_USER_AGENT_STR(mUserAgent.c_str()), TAG_END());

	string contact_string{sip_header_as_string(home.home(), (sip_header_t const*)contact)};
	return contact_string;
}

static std::string extractStringParam(url_t* url, const char* param) noexcept {
	if (!url_has_param(url, param)) {
		return string{};
	}

	string buffer(255, '\0');
	auto valueLength = url_param(url->url_params, param, &buffer[0], buffer.size());
	buffer.resize(valueLength - 1);
	url->url_params = url_strip_param_string(const_cast<char*>(url->url_params), param);
	return UriUtils::unescape(buffer);
}

static int extractIntParam(url_t* url, const char* param) noexcept {
	try {
		return stoi(extractStringParam(url, param));
	} catch (...) {
		return 0;
	}
}

static int extractUnsignedLongParam(url_t* url, const char* param) noexcept {
	try {
		return static_cast<int>(stoll(extractStringParam(url, param)));
	} catch (...) {
		return 0;
	}
}

static bool extractBoolParam(url_t* url, const char* param) noexcept {
	auto extractedParam = extractStringParam(url, param);
	return !extractedParam.empty() && extractedParam.find("yes") != string::npos;
}

void ExtendedContact::init(bool initExpire) {
	if (mSipContact) {
		if (mSipContact->m_q) {
			mQ = atof(mSipContact->m_q);
		}

		if (url_has_param(mSipContact->m_url, "fs-conn-id")) {
			char strConnId[32] = {0};
			if (url_param(mSipContact->m_url->url_params, "fs-conn-id", strConnId, sizeof(strConnId) - 1) > 0) {
				mConnId = std::strtoull(strConnId, nullptr, 16);
			}
		}

		if (initExpire) {
			int expire = resolveExpire(mSipContact->m_expires, mExpireNotAtMessage);
			mExpireNotAtMessage = mUpdatedTime + expire;
			expire = resolveExpire(getMessageExpires(mSipContact->m_params).c_str(), expire);
			if (expire == -1) {
				LOGE("no global expire (%li) nor local contact expire (%s)found", mExpireNotAtMessage,
				     mSipContact->m_expires);
				expire = 0;
			}
			mExpireAt = mUpdatedTime + expire;
			mExpireAt = mExpireAt > mExpireNotAtMessage ? mExpireAt : mExpireNotAtMessage;
		}
		auto pnProvider = UriUtils::getParamValue(mSipContact->m_url->url_params, "pn-provider");
		auto pnPrId = UriUtils::getParamValue(mSipContact->m_url->url_params, "pn-prid");
		auto pnParam = UriUtils::getParamValue(mSipContact->m_url->url_params, "pn-param");
		if (!pnProvider.empty() && !pnPrId.empty() && !pnParam.empty()) {
			mPushParamList = PushParamList{pnProvider, pnPrId, pnParam};
		} else {
			auto appId = UriUtils::getParamValue(mSipContact->m_url->url_params, "app-id");
			auto pnType = UriUtils::getParamValue(mSipContact->m_url->url_params, "pn-type");
			auto pnTok = UriUtils::getParamValue(mSipContact->m_url->url_params, "pn-tok");
			if (!appId.empty() && !pnType.empty() && !pnTok.empty()) {
				mPushParamList = PushParamList{pnType, pnTok, appId, true};
			}
		}
	}
}

void ExtendedContact::extractInfoFromUrl(const char* full_url) {
	sip_contact_t* temp_contact = sip_contact_make(mHome.home(), full_url);
	url_t* url = nullptr;
	if (temp_contact == nullptr) {
		SLOGD << "Couldn't parse " << full_url << " as contact, fallback to url instead";
		url = url_make(mHome.home(), full_url);
	} else {
		url = temp_contact->m_url;
	}

	if (url == nullptr) {
		LOGE("ExtendedContact::extractInfoFromUrl() url is null.");
		return;
	}

	// CallId
	mCallId = extractStringParam(url, "callid");

	// Expire
	mExpireNotAtMessage = extractIntParam(url, "expires");

	// Update time
	mUpdatedTime = extractUnsignedLongParam(url, "updatedAt");

	// CSeq
	mCSeq = extractIntParam(url, "cseq");

	// Alias
	mAlias = extractBoolParam(url, "alias");

	// Used as route
	mUsedAsRoute = extractBoolParam(url, "usedAsRoute");

	extractInfoFromHeader(url->url_headers);

	char transport[20] = {0};
	url_param(url[0].url_params, "transport", transport, sizeof(transport) - 1);

	url->url_headers = nullptr;

	if (temp_contact == nullptr) {
		mSipContact = sip_contact_create(mHome.home(), (url_string_t*)url, nullptr);
	} else {
		mSipContact = temp_contact;
	}
}

bool ExtendedContact::isSame(const ExtendedContact& otherContact) const {
	return mCallId == otherContact.mCallId && getUniqueId() == otherContact.getUniqueId() &&
	       url_cmp_all(mSipContact->m_url, otherContact.mSipContact->m_url) == 0;
	/* FIXME: the comparison is not complete */
}

InvalidAorError::InvalidAorError(const url_t* aor) : invalid_argument("") {
	mAor = url_as_string(mHome.home(), aor);
}

bool Record::updateFromUrlEncodedParams(const char* uid,
                                        const char* full_url,
                                        const shared_ptr<ContactUpdateListener>& listener) {
	auto exc = make_shared<ExtendedContact>(uid, full_url);

	if (exc->mSipContact) {
		insertOrUpdateBinding(exc, listener);
		return true;
	}
	return false;
}

void Record::eliminateAmbiguousContacts(list<shared_ptr<ExtendedContact>>& extendedContacts) {
	/* This happens when a client (like Linphone) sends this kind of very ambiguous Contact header in a REGISTER
	 * Contact:
	 * <sip:marie_-jSau@ip1:39936;transport=tcp>;+sip.instance="<urn:uuid:bfb7514b-f793-4d85-b322-232044dc3731>"
	 * Contact:
	 * <sip:marie_-jSau@ip1:39934;transport=tcp>;+sip.instance="<urn:uuid:bfb7514b-f793-4d85-b322-232044dc3731>";expires=0
	 * We want to drop the second one.
	 */
	for (auto it = extendedContacts.begin(); it != extendedContacts.end();) {
		shared_ptr<ExtendedContact> exc = *it;
		if (exc->mUpdatedTime == exc->mExpireAt && !exc->mUniqueId.empty()) {
			auto duplicate = find_if(extendedContacts.begin(), extendedContacts.end(),
			                         [exc](const shared_ptr<ExtendedContact>& exc2) -> bool {
				                         return exc != exc2 && exc->mUniqueId == exc2->mUniqueId;
			                         });
			if (duplicate != extendedContacts.end()) {
				LOGD("Eliminating duplicate contact with unique id [%s]", exc->mUniqueId.c_str());
				it = extendedContacts.erase(it);
				continue;
			}
		}
		++it;
	}
}

void Record::update(const sip_t* sip,
                    const BindingParameters& parameters,
                    const shared_ptr<ContactUpdateListener>& listener) {
	list<string> stlPath;
	sofiasip::Home home;
	string userAgent;
	const sip_contact_t* contacts = sip->sip_contact;
	const sip_accept_t* accept = sip->sip_accept;
	list<string> acceptHeaders;
	list<shared_ptr<ExtendedContact>> extendedContacts;

	while (accept != nullptr) {
		acceptHeaders.push_back(accept->ac_type);
		accept = accept->ac_next;
	}

	if (sip->sip_path != nullptr) {
		stlPath = route_to_stl(sip->sip_path);
	}

	userAgent = (sip->sip_user_agent) ? sip->sip_user_agent->g_string : "";

	// Build ExtendedContacts from sip contacts.
	while (contacts) {
		string uniqueId = extractUniqueId(contacts);

		ExtendedContactCommon ecc(stlPath, sip->sip_call_id->i_id, uniqueId);
		bool alias = parameters.isAliasFunction ? parameters.isAliasFunction(contacts->m_url) : parameters.alias;
		auto exc = make_shared<ExtendedContact>(ecc, contacts, parameters.globalExpire,
		                                        (sip->sip_cseq) ? sip->sip_cseq->cs_seq : 0, getCurrentTime(), alias,
		                                        acceptHeaders, userAgent);
		exc->mUsedAsRoute = sip->sip_from->a_url->url_user == nullptr;
		extendedContacts.push_back(exc);
		contacts = contacts->m_next;
	}

	eliminateAmbiguousContacts(extendedContacts);

	// Update the Record.
	for (auto exc : extendedContacts) {
		insertOrUpdateBinding(exc, listener);
	}

	applyMaxAor();

	SLOGD << *this;
}

void Record::update(const ExtendedContactCommon& ecc,
                    const char* sipuri,
                    long expireAt,
                    float q,
                    uint32_t cseq,
                    time_t updated_time,
                    bool alias,
                    const list<string> accept,
                    bool usedAsRoute,
                    const shared_ptr<ContactUpdateListener>& listener) {
	sofiasip::Home home;
	url_t* sipUri = url_make(home.home(), sipuri);

	if (!sipUri) {
		LOGE("Record::update(): could not build sip uri.");
		return;
	}
	sip_contact_t* contact = sip_contact_create(home.home(), (url_string_t*)sipUri, nullptr);
	if (!contact) {
		LOGE("Record::update(): could not build contact.");
		return;
	}

	auto exct = make_shared<ExtendedContact>(ecc, contact, expireAt, cseq, updated_time, alias, accept, "");
	exct->mUsedAsRoute = usedAsRoute;
	insertOrUpdateBinding(exct, listener);
	applyMaxAor();

	SLOGD << *this;
}

/* This function is designed for non-regression tests. It is not performant and non-exhaustive in the compararison */
bool Record::isSame(const Record& other) const {
	if (getAor() != other.getAor()) {
		LOGD("Record::isSame(): aors differ.");
		return false;
	}
	if (getExtendedContacts().size() != other.getExtendedContacts().size()) {
		LOGD("Record::isSame(): number of extended contacts differ.");
		return false;
	}
	for (const auto& exc : getExtendedContacts()) {
		const auto& otherExc = extractContactByUniqueId(exc->getUniqueId());
		if (otherExc == nullptr) {
			LOGD("Record::isSame(): no contact with uniqueId [%s] in other record.", exc->getUniqueId().c_str());
			return false;
		}
		if (!exc->isSame(*otherExc)) {
			SLOGD << "Record::isSame(): contacts differ: [" << *this << "] <> [" << *otherExc << "]";
			return false;
		}
	}
	return true;
}

void Record::print(ostream& stream) const {
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

Record::Record(const SipUri& aor) : Record(SipUri(aor)) {
}

Record::Record(SipUri&& aor) : mAor(move(aor)) {
	// warning: aor is empty at this point. Use mAor!
	mKey = defineKeyFromUrl(mAor.get());
	mIsDomain = mAor.getUser().empty();
	if (sMaxContacts == -1) init();
}

url_t* Record::getPubGruu(const std::shared_ptr<ExtendedContact>& ec, su_home_t* home) {
	char gr_value[256] = {0};
	url_t* gruu_addr = NULL;
	const char* pub_gruu_value = msg_header_find_param((msg_common_t*)ec->mSipContact, "pub-gruu");

	if (pub_gruu_value) {
		if (pub_gruu_value[0] == '\0') {
			/*
			 * To preserve compatibility with previous storage of pub-gruu (where only a gr parameter was set in URI),
			 * a client that didn't requested a gruu address has now a "pub-gruu" contact parameter which is empty.
			 * This means that this client has no pub-gruu assigned by this server.
			 */
			return nullptr;
		}
		gruu_addr = url_make(home, StringUtils::unquote(pub_gruu_value).c_str());
		return gruu_addr;
	}

	/*
	 * Compatibility code, when pub-gruu wasn't stored in RegistrarDb.
	 * In such case, we have to synthetize the gruu address from the address of record and the gr uri parameter.
	 */

	if (!ec->mSipContact->m_url->url_params) return NULL;
	isize_t result = url_param(ec->mSipContact->m_url->url_params, "gr", gr_value, sizeof(gr_value) - 1);

	if (result > 0) {
		gruu_addr = url_hdup(home, mAor.get());
		url_param_add(home, gruu_addr, su_sprintf(home, "gr=%s", gr_value));
	}
	return gruu_addr;
}

void Record::init() {
	GenericStruct* registrar = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	sMaxContacts = registrar->get<ConfigInt>("max-contacts-by-aor")->read();
	sLineFieldNames = registrar->get<ConfigStringList>("unique-id-parameters")->read();
	sAssumeUniqueDomains = GenericManager::get()
	                           ->getRoot()
	                           ->get<GenericStruct>("inter-domain-connections")
	                           ->get<ConfigBoolean>("assume-unique-domains")
	                           ->read();
}

void Record::appendContactsFrom(const shared_ptr<Record>& src) {
	if (!src) return;

	for (auto it = src->mContacts.begin(); it != src->mContacts.end(); ++it) {
		mContacts.push_back(*it);
	}
}

RegistrarDb::LocalRegExpire::LocalRegExpire(Agent* ag) : mAgent(ag) {
}

RegistrarDb::RegistrarDb(Agent* ag) : mLocalRegExpire(new LocalRegExpire(ag)), mAgent(ag), mUseGlobalDomain(false) {
	GenericStruct* cr = GenericManager::get()->getRoot();
	GenericStruct* mr = cr->get<GenericStruct>("module::Registrar");
	mGruuEnabled = mr->get<ConfigBoolean>("enable-gruu")->read();
}

RegistrarDb::~RegistrarDb() {
	delete mLocalRegExpire;
}

void RegistrarDb::addStateListener(const std::shared_ptr<RegistrarDbStateListener>& listener) {
	auto it = find(mStateListeners.cbegin(), mStateListeners.cend(), listener);
	if (it == mStateListeners.cend()) mStateListeners.push_back(listener);
}

void RegistrarDb::removeStateListener(const std::shared_ptr<RegistrarDbStateListener>& listener) {
	mStateListeners.remove(listener);
}

void RegistrarDb::notifyStateListener() const {
	for (auto& listener : mStateListeners)
		listener->onRegistrarDbWritable(mWritable);
}

void RegistrarDb::subscribe(const SipUri& url, const shared_ptr<ContactRegisteredListener>& listener) {
	this->subscribe(Record::defineKeyFromUrl(url.get()), listener);
}

bool RegistrarDb::subscribe(const string& topic, const shared_ptr<ContactRegisteredListener>& listener) {
	const auto& alreadyRegisteredListener = mContactListenersMap.equal_range(topic);

	const auto listenerAlreadyPresent =
	    find_if(alreadyRegisteredListener.first, alreadyRegisteredListener.second, [&listener](const auto& mapEntry) {
		    return mapEntry.second == listener;
	    }) != alreadyRegisteredListener.second;
	if (listenerAlreadyPresent) {
		LOGD("Already subscribe topic = %s with listener %p", topic.c_str(), listener.get());
		return false;
	}

	LOGD("Subscribe topic = %s with listener %p", topic.c_str(), listener.get());
	mContactListenersMap.emplace(topic, listener);

	return true;
}

void RegistrarDb::unsubscribe(const string& topic, const shared_ptr<ContactRegisteredListener>& listener) {
	LOGD("Unsubscribe topic = %s with listener %p", topic.c_str(), listener.get());
	bool found = false;
	auto range = mContactListenersMap.equal_range(topic);
	for (auto it = range.first; it != range.second;) {
		if (it->second == listener) {
			found = true;
			it = mContactListenersMap.erase(it);
		} else it++;
	}
	if (!found) {
		LOGE("RegistrarDb::unsubscribe() for topic %s and listener = %p is invalid.", topic.c_str(), listener.get());
	}
}

class ContactNotificationListener : public ContactUpdateListener,
                                    public std::enable_shared_from_this<ContactNotificationListener> {
public:
	ContactNotificationListener(const string& uid, RegistrarDb* db, const SipUri& aor) : mUid(uid), mDb(db), mAor(aor) {
	}

private:
	// ContactUpdateListener implementation
	void onRecordFound(const shared_ptr<Record>& r) override {
		auto record = r ?: make_shared<Record>(mAor);
		mDb->notifyContactListener(record, mUid);
	}
	void onError() override {
	}
	void onInvalid() override {
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>& ec) override {
	}

	string mUid;
	RegistrarDb* mDb = nullptr;
	SipUri mAor;
};

void RegistrarDb::notifyContactListener(const string& key, const string& uid) {
	auto sipUri = Record::makeUrlFromKey(key);
	auto listener = make_shared<ContactNotificationListener>(uid, this, sipUri);
	LOGD("Notify topic = %s, uid = %s", key.c_str(), uid.c_str());
	RegistrarDb::get()->fetch(sipUri, listener, true);
}

void RegistrarDb::notifyContactListener(const shared_ptr<Record>& r, const string& uid) {
	auto range = mContactListenersMap.equal_range(r->getKey());

	/* Because invoking the listener might indirectly unregister listeners from the RegistrarDb, it is required
	 * to first create a local copy of the list of listeners we are going to invoke. */
	vector<shared_ptr<ContactRegisteredListener>> listeners{};
	for (auto it = range.first; it != range.second; it++) {
		listeners.emplace_back(it->second);
	}
	for (const auto& l : listeners) {
		LOGD("Notify topic = %s to listener %p", r->getKey().c_str(), l.get());
		l->onContactRegistered(r, uid);
	}
}

void RegistrarDb::LocalRegExpire::update(const shared_ptr<Record>& record) {
	unique_lock<mutex> lock(mMutex);
	time_t latest = record->latestExpire(mAgent);
	if (latest > 0) {
		auto it = mRegMap.find(record->getKey());
		if (it != mRegMap.end()) {
			(*it).second = latest;
		} else {
			if (!record->isEmpty() && !record->haveOnlyStaticContacts()) {
				mRegMap.insert(make_pair(record->getKey(), latest));
				notifyLocalRegExpireListener(mRegMap.size());
			}
		}
	} else {
		mRegMap.erase(record->getKey());
		notifyLocalRegExpireListener(mRegMap.size());
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
			notifyLocalRegExpireListener(mRegMap.size());
		} else {
			++it;
		}
	}
}

void RegistrarDb::LocalRegExpire::getRegisteredAors(std::list<std::string>& aors) const {
	unique_lock<mutex> lock(mMutex);
	for (auto& pair : mRegMap) {
		aors.push_back(pair.first);
	}
}

void RegistrarDb::LocalRegExpire::subscribe(LocalRegExpireListener* listener) {
	LOGD("Subscribe LocalRegExpire");
	mLocalRegListenerList.push_back(listener);
}

void RegistrarDb::LocalRegExpire::unsubscribe(LocalRegExpireListener* listener) {
	LOGD("Unsubscribe LocalRegExpire");
	auto result = find(mLocalRegListenerList.begin(), mLocalRegListenerList.end(), listener);
	if (result != mLocalRegListenerList.end()) {
		mLocalRegListenerList.erase(result);
	}
}

void RegistrarDb::LocalRegExpire::notifyLocalRegExpireListener(unsigned int count) {
	LOGD("Notify LocalRegExpire count = %d", count);
	for (auto listener : mLocalRegListenerList) {
		listener->onLocalRegExpireUpdated(count);
	}
}

int RegistrarDb::countSipContacts(const sip_contact_t* contact) {
	int count = 0;
	sip_contact_t* current = (sip_contact_t*)contact;
	while (current) {
		if (!current->m_expires || atoi(current->m_expires) != 0) {
			++count;
		}
		current = current->m_next;
	}
	return count;
}

bool RegistrarDb::errorOnTooMuchContactInBind(const sip_contact_t* sip_contact,
                                              const string& key,
                                              const shared_ptr<RegistrarDbListener>& listener) {
	int nb_contact = this->countSipContacts(sip_contact);
	int max_contact = Record::getMaxContacts();
	if (nb_contact > max_contact) {
		LOGD("Too many contacts in register %s %i > %i", key.c_str(), nb_contact, max_contact);
		return true;
	}

	return false;
}

unique_ptr<RegistrarDb> RegistrarDb::sUnique = nullptr;

void RegistrarDb::resetDB() {
	SLOGW << "Reseting RegistrarDb static pointer, you MUST be in a test.";
	sUnique = nullptr;
}

RegistrarDb* RegistrarDb::initialize(Agent* ag) {
	if (sUnique != nullptr) {
		LOGF("RegistrarDb already initialized");
	}
	GenericStruct* cr = GenericManager::get()->getRoot();
	GenericStruct* mr = cr->get<GenericStruct>("module::Registrar");
	GenericStruct* mro = cr->get<GenericStruct>("module::Router");

	bool useGlobalDomain = mro->get<ConfigBoolean>("use-global-domain")->read();
	string dbImplementation = mr->get<ConfigString>("db-implementation")->read();
	string mMessageExpiresName = mr->get<ConfigString>("message-expires-param-name")->read();

	if ("internal" == dbImplementation) {
		LOGI("RegistrarDB implementation is internal");
		sUnique = make_unique<RegistrarDbInternal>(ag);
		sUnique->mUseGlobalDomain = useGlobalDomain;
	}
#ifdef ENABLE_REDIS
	/* Previous implementations allowed "redis-sync" and "redis-async", whereas we now expect "redis".
	 * We check that the dbImplementation _starts_ with "redis" now, so that we stay backward compatible. */
	else if (dbImplementation.find("redis") == 0) {
		LOGI("RegistrarDB implementation is REDIS");
		GenericStruct* registrar = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
		RedisParameters params;
		params.domain = registrar->get<ConfigString>("redis-server-domain")->read();
		params.port = registrar->get<ConfigInt>("redis-server-port")->read();
		params.timeout = registrar->get<ConfigInt>("redis-server-timeout")->read();
		params.auth = registrar->get<ConfigString>("redis-auth-password")->read();
		params.mSlaveCheckTimeout = chrono::seconds{registrar->get<ConfigInt>("redis-slave-check-period")->read()};
		params.useSlavesAsBackup = registrar->get<ConfigBoolean>("redis-use-slaves-as-backup")->read();

		sUnique = make_unique<RegistrarDbRedisAsync>(ag, params);
		sUnique->mUseGlobalDomain = useGlobalDomain;
		static_cast<RegistrarDbRedisAsync*>(sUnique.get())->connect();
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
	return sUnique.get();
}

RegistrarDb* RegistrarDb::get() {
	if (sUnique == nullptr) {
		LOGF("RegistrarDb not initialized.");
	}
	return sUnique.get();
}

void RegistrarDb::clear(const MsgSip& sip, const shared_ptr<ContactUpdateListener>& listener) {
	doClear(sip, listener);
}

void RegistrarDb::clear(const SipUri& url,
                        const std::string& callId,
                        const std::shared_ptr<ContactUpdateListener>& listener) {
	// Forged message
	MsgSip msg(ownership::owned(nta_msg_create(mAgent->getSofiaAgent(), 0)));
	auto home = msg.getHome();
	auto sip = msg.getSip();
	sip->sip_from = sip_from_create(home, reinterpret_cast<const url_string_t*>(url.get()));
	sip->sip_call_id = sip_call_id_make(home, callId.c_str());
	sip->sip_cseq = sip_cseq_create(home, 0xDEADC0DE, SIP_METHOD_REGISTER); // Placeholder
	clear(msg, listener);
}

const string RegistrarDb::getMessageExpires(const msg_param_t* m_params) {
	if (m_params) {
		// Find message expires time in the contact parameters
		string mss_expires(*m_params);
		string name_expires_mss = RegistrarDb::get()->messageExpiresName();
		if (mss_expires.find(name_expires_mss + "=") != string::npos) {
			mss_expires =
			    mss_expires.substr(mss_expires.find(name_expires_mss + "=") + (strlen(name_expires_mss.c_str()) + 1));
			return mss_expires;
		}
	}
	return "";
}

class RecursiveRegistrarDbListener : public ContactUpdateListener,
                                     public enable_shared_from_this<RecursiveRegistrarDbListener> {
private:
	sofiasip::Home mHome;
	RegistrarDb* mDatabase = nullptr;
	shared_ptr<ContactUpdateListener> mOriginalListener;
	shared_ptr<Record> mRecord;
	int mPendingRequests = 1;
	int mStep = 0;
	SipUri mUrl;
	float mOriginalQ = 1.0; // the q parameter. When recursing, we choose to inherit it from the original target.
	bool mRecursionDone = false;
	static int sMaxStep;

public:
	RecursiveRegistrarDbListener(RegistrarDb* database,
	                             const shared_ptr<ContactUpdateListener>& original_listerner,
	                             const SipUri& url,
	                             int step = sMaxStep)
	    : mDatabase(database), mOriginalListener(original_listerner), mRecord(make_shared<Record>(url)), mStep(step),
	      mUrl(url) {
	}

	void onRecordFound(const shared_ptr<Record>& r) override {
		mPendingRequests--;
		if (r != nullptr) {
			auto& extlist = r->getExtendedContacts();
			list<shared_ptr<ExtendedContact>> vectToRecurseOn;
			for (auto ec : extlist) {
				// Also add alias for late forking (context in the forks map for this alias key)
				SLOGD << "Step: " << mStep << (ec->mAlias ? "\tFound alias " : "\tFound contact ") << mUrl << " -> "
				      << ExtendedContact::urlToString(ec->mSipContact->m_url) << " usedAsRoute:" << ec->mUsedAsRoute;
				if (!ec->mAlias && ec->mUsedAsRoute) {
					ec = transformContactUsedAsRoute(mUrl.str(), ec);
				}
				mRecord->pushContact(ec);
				ec->mQ = ec->mQ * mOriginalQ;
				if (ec->mAlias && mStep > 0 && !mRecursionDone) {
					vectToRecurseOn.push_back(ec);
				}
			}
			mPendingRequests += vectToRecurseOn.size();
			mRecursionDone = true;
			for (auto itrec : vectToRecurseOn) {
				try {
					SipUri uri(itrec->mSipContact->m_url);
					auto listener =
					    make_shared<RecursiveRegistrarDbListener>(mDatabase, this->shared_from_this(), uri, mStep - 1);
					listener->mOriginalQ = itrec->mQ;
					mDatabase->fetch(uri, listener, false);
				} catch (const sofiasip::InvalidUrlError& e) {
					SLOGE << "Invalid fetched URI while fetching [" << mUrl.str() << "] recusively." << endl
					      << "The invalid URI is [" << e.getUrl() << "]. Reason: " << e.getReason();
				}
			}
		}

		if (waitPullUpOrFail()) {
			SLOGD << "Step: " << mStep << "\tNo contact found for " << mUrl;
			mOriginalListener->onRecordFound(nullptr);
		}
	}

	void onError() override {
		SLOGW << "Step: " << mStep << "\tError during recursive fetch of " << mUrl;
		if (waitPullUpOrFail()) {
			mOriginalListener->onError();
		}
	}

	void onInvalid() override {
		SLOGW << "Step: " << mStep << "\tInvalid during recursive fetch of " << mUrl;
		if (waitPullUpOrFail()) {
			mOriginalListener->onInvalid();
		}
	}

	void onContactUpdated(const shared_ptr<ExtendedContact>& ec) override {
	}

private:
	shared_ptr<ExtendedContact> transformContactUsedAsRoute(const std::string& uri,
	                                                        const shared_ptr<ExtendedContact>& ec) {
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
		newEc->mSipContact =
		    sip_contact_create(newEc->mHome.home(), reinterpret_cast<const url_string_t*>(uri.c_str()), nullptr);
		ostringstream path;
		path << *ec->toSofiaUrlClean(newEc->mHome.home());
		newEc->mPath.push_back(path.str());
		// LOGD("transformContactUsedAsRoute(): path to %s added for %s", ec->mSipUri.c_str(), uri);
		newEc->mUsedAsRoute = false;
		return newEc;
	}

	bool waitPullUpOrFail() {
		if (mPendingRequests != 0) return false; // wait for all pending responses

		// No more results expected for this recursion level
		if (mRecord->getExtendedContacts().empty()) {
			return true; // no contacts collected on below recursion levels
		}

		// returning records collected on below recursion levels
		SLOGD << "Step: " << mStep << "\tReturning collected records " << mRecord->getExtendedContacts().size();
		mOriginalListener->onRecordFound(mRecord);
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

LocalRegExpireListener::~LocalRegExpireListener() {
}

void RegistrarDb::fetch(const SipUri& url, const shared_ptr<ContactUpdateListener>& listener, bool recursive) {
	fetch(url, listener, false, recursive);
}

void RegistrarDb::fetch(const SipUri& url,
                        const shared_ptr<ContactUpdateListener>& listener,
                        bool includingDomains,
                        bool recursive) {
	if (includingDomains) {
		fetchWithDomain(url, listener, recursive);
		return;
	}
	auto gr = UriUtils::getParamValue(url.get()->url_params, "gr");
	if (!gr.empty()) {
		doFetchInstance(url, UriUtils::grToUniqueId(gr),
		                recursive ? make_shared<RecursiveRegistrarDbListener>(this, listener, url) : listener);
	} else {
		doFetch(url, recursive ? make_shared<RecursiveRegistrarDbListener>(this, listener, url) : listener);
	}
}

void RegistrarDb::fetchList(const vector<SipUri> urls, const shared_ptr<ListContactUpdateListener>& listener) {
	class InternalContactUpdateListener : public ContactUpdateListener {
	public:
		InternalContactUpdateListener(shared_ptr<ListContactUpdateListener> listener, size_t size)
		    : listListener(listener), count(size) {
		}

	private:
		void onError() override {
			SLOGE << "Error while fetching contact";
			updateCount();
		}
		void onInvalid() override {
			SLOGE << "Invalid fetch of contact";
			updateCount();
		}
		void onRecordFound(const shared_ptr<Record>& r) override {
			SLOGI << "Contact fetched";
			if (r) listListener->records.push_back(r);
			updateCount();
		}
		void onContactUpdated(const shared_ptr<ExtendedContact>& ec) override {
		}
		void updateCount() {
			count--;
			if (count == 0) listListener->onContactsUpdated();
		}

		shared_ptr<ListContactUpdateListener> listListener;
		size_t count;
	};

	shared_ptr<InternalContactUpdateListener> urlListener =
	    make_shared<InternalContactUpdateListener>(listener, urls.size());
	for (const auto& url : urls) {
		fetch(url, urlListener);
	}
}

url_t* RegistrarDb::synthesizePubGruu(su_home_t* home, const MsgSip& sipMsg) {
	sip_t* sip = sipMsg.getSip();
	if (!sip->sip_contact || !sip->sip_contact->m_params) return nullptr;
	if (!sip->sip_supported || msg_params_find(sip->sip_supported->k_items, "gruu") == nullptr) return nullptr;
	const char* instance_param = msg_params_find(sip->sip_contact->m_params, "+sip.instance");
	if (!instance_param) return nullptr;

	string gr = UriUtils::uniqueIdToGr(instance_param);
	if (gr.empty()) return nullptr;
	url_t* gruuUri = url_hdup(home, sip->sip_from->a_url);
	url_param_add(home, gruuUri, (string("gr=") + gr).c_str());
	return gruuUri;
}

void RegistrarDb::bind(const MsgSip& sipMsg,
                       const BindingParameters& parameter,
                       const shared_ptr<ContactUpdateListener>& listener) {
	/* Copy the SIP message because the below code modifies the message whereas bind() API suggests that it does not. */
	MsgSip msgCopy{sipMsg};
	sip_t* sip = msgCopy.getSip();

	bool gruu_assigned = false;
	if (mGruuEnabled) {
		url_t* gruuUri = synthesizePubGruu(msgCopy.getHome(), msgCopy);
		if (gruuUri) {
			/* assign a public gruu address to this contact */
			msg_header_replace_param(
			    msgCopy.getHome(), (msg_common_t*)sip->sip_contact,
			    su_sprintf(msgCopy.getHome(), "pub-gruu=\"%s\"", url_as_string(msgCopy.getHome(), gruuUri)));
			gruu_assigned = true;
		}
	}
	if (!gruu_assigned) {
		/* Set an empty pub-gruu meaning that this client hasn't requested any pub-gruu from this server.
		 * This is to preserve compatibility with previous RegistrarDb storage, where only gr parameter was stored.
		 * This couldn't work because a client can use a "gr" parameter in its contact uri.*/
		msg_header_replace_param(msgCopy.getHome(), (msg_common_t*)sip->sip_contact,
		                         su_sprintf(msgCopy.getHome(), "pub-gruu"));
	}

	int countSipContacts = this->countSipContacts(sip->sip_contact);
	if (countSipContacts > Record::getMaxContacts()) {
		LOGD("Too many contacts in register %s %i > %i", Record::defineKeyFromUrl(sip->sip_from->a_url).c_str(),
		     countSipContacts, Record::getMaxContacts());
		listener->onError();
		return;
	}

	doBind(msgCopy, parameter, listener);
}

void RegistrarDb::bind(const SipUri& from,
                       const sip_contact_t* contact,
                       const BindingParameters& parameter,
                       const shared_ptr<ContactUpdateListener>& listener) {
	MsgSip msg{};
	auto* homeSip = msg.getHome();
	auto* sip = msg.getSip();

	sip->sip_contact = sip_contact_dup(homeSip, contact);

	sip->sip_from = sip_from_create(homeSip, reinterpret_cast<const url_string_t*>(from.get()));

	if (!parameter.path.empty()) {
		sip->sip_path = sip_path_format(homeSip, "<%s>", parameter.path.c_str());
	}

	if (!parameter.userAgent.empty()) {
		sip->sip_user_agent = sip_user_agent_make(homeSip, parameter.userAgent.c_str());
	}

	if (parameter.withGruu) {
		sip->sip_supported =
		    reinterpret_cast<sip_supported_t*>(sip_header_format(homeSip, sip_supported_class, "gruu"));
	}

	if (!parameter.callId.empty()) {
		sip->sip_call_id = sip_call_id_make(homeSip, parameter.callId.c_str());
	}

	sip->sip_expires = sip_expires_create(homeSip, 0);

	bind(msg, parameter, listener);
}

class AgregatorRegistrarDbListener : public ContactUpdateListener {
private:
	shared_ptr<ContactUpdateListener> mOriginalListener;
	int mNumRespExpected;
	int mNumResponseObtained;
	shared_ptr<Record> mRecord;
	bool mError;
	shared_ptr<Record> getRecord() {
		if (mRecord == nullptr) mRecord = make_shared<Record>(SipUri{});
		return mRecord;
	}
	void checkFinished() {
		mNumResponseObtained++;
		if (mNumResponseObtained == mNumRespExpected) {
			if (mError && mRecord == nullptr) {
				mOriginalListener->onError();
			} else {
				mOriginalListener->onRecordFound(mRecord);
			}
		}
	}

public:
	AgregatorRegistrarDbListener(const shared_ptr<ContactUpdateListener>& origListener, int numResponseExpected)
	    : mOriginalListener(origListener), mNumRespExpected(numResponseExpected), mNumResponseObtained(0), mRecord(0) {
		mError = false;
	}
	virtual ~AgregatorRegistrarDbListener() {
	}
	virtual void onRecordFound(const shared_ptr<Record>& r) override {
		if (r) {
			getRecord()->appendContactsFrom(r);
		}
		checkFinished();
	}
	virtual void onError() override {
		mError = true;
		checkFinished();
	}
	virtual void onInvalid() override {
		// onInvalid() will normally never be called for a fetch request
		checkFinished();
	}

	virtual void onContactUpdated(const shared_ptr<ExtendedContact>& ec) override {
	}
};

void RegistrarDb::fetchWithDomain(const SipUri& url,
                                  const shared_ptr<ContactUpdateListener>& listener,
                                  bool recursive) {
	if (!url.getUser().empty()) {
		/* If username is present in URI, search with and without the username */
		auto domainOnlyUrl = url.replaceUser("");
		auto agregator = make_shared<AgregatorRegistrarDbListener>(listener, 2);
		fetch(url, agregator, recursive);
		fetch(domainOnlyUrl, agregator, false);
	} else {
		/* else do a single search of course. */
		fetch(url, listener, recursive);
	}
}

RecordSerializer* RecordSerializer::create(const string& name) {
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
	else if (name == "msgpack") {
		return new RecordSerializerMsgPack();
	}
#endif
	else {
		return nullptr;
	}
}

RecordSerializer* RecordSerializer::sInstance = nullptr;

RecordSerializer* RecordSerializer::get() {
	if (!sInstance) {
		string name = "protobuf";
		sInstance = create(name);
		if (!sInstance) {
			LOGF("Unsupported record serializer: '%s'", name.c_str());
		}
	}
	return sInstance;
}
