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

#include "module.hh"
#include "agent.hh"
#include "registrardb.hh"
#include "log/logmanager.hh"

#include <sofia-sip/sip_status.h>
#include <fstream>
#include <sstream>
#include <ostream>
#include <csignal>

#include <functional>
#include <algorithm>

using namespace std;

class ModuleRegistrar;
static ModuleRegistrar *sRegistrarInstanceForSigAction = NULL;

class FakeFetchListener : public RegistrarDbListener {
	friend class ModuleRegistrar;

  public:
	FakeFetchListener() {
	}
	void onRecordFound(Record *r) {
		if (r != NULL) {
			SLOGD << r;
		} else {
			LOGD("No record found");
		}
	}
	void onError() {
	}

	void onInvalid() {
		LOGD("FakeFetchListener: onInvalid");
	}
};

struct RegistrarStats {
	unique_ptr<StatPair> mCountBind;
	unique_ptr<StatPair> mCountClear;
	StatCounter64 *mCountLocalActives;
};

class OnRequestBindListener;
class OnResponseBindListener;
class ResponseContext;
class ModuleRegistrar : public Module, public ModuleToolbox {
	friend class OnRequestBindListener;
	friend class OnResponseBindListener;
	RegistrarStats mStats;
	static void staticRoutesRereadTimerfunc(su_root_magic_t *magic, su_timer_t *t, void *data) {
		ModuleRegistrar *r = (ModuleRegistrar *)data;
		r->readStaticRecords();
	}

  public:
	void reply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason, const sip_contact_t *contacts = NULL);
	void reply(shared_ptr<ResponseSipEvent> &ev, int code, const char *reason, const sip_contact_t *contacts = NULL);

	void routeRequest(shared_ptr<RequestSipEvent> &ev, Record *aorb, const url_t *sipUri);

	ModuleRegistrar(Agent *ag) : Module(ag), mStaticRecordsTimer(NULL) {
		sRegistrarInstanceForSigAction = this;
		memset(&mSigaction, 0, sizeof(mSigaction));
		mStaticRecordsVersion = 0;
	}

	~ModuleRegistrar() {
	}

	virtual void onDeclare(GenericStruct *mc) {
		ConfigItemDescriptor configs[] = {
			{StringList, "reg-domains", "List of whitespace separated domain names to be managed by the registrar."
										" It can eventually be the '*' (wildcard) in order to match any domain name.",
			 "localhost"},
			{Boolean, "reg-on-response",
			 "Register users based on response obtained from a back-end server. "
			 "This mode is for using flexisip as a front-end server to hold client connections but register"
			 "acceptance is deferred to backend server to which the REGISTER is routed.",
			 "false"},
			{Integer, "max-contacts-by-aor", "Maximum number of registered contacts of an address of record.",
			 "12"}, /*used by registrardb*/
			{StringList, "unique-id-parameters",
			 "List of contact uri parameters that can be used to identify a user's device. "
			 "The contact parameters are searched in the order of the list, the first matching parameter is used and "
			 "the others ignored.",
			 "+sip.instance pn-tok line"},

			{Integer, "max-expires", "Maximum expire time for a REGISTER, in seconds.", "86400"},
			{Integer, "min-expires", "Minimum expire time for a REGISTER, in seconds.", "60"},
			{Integer, "force-expires", "Set a value that will override expire times given by "
										"REGISTER requests. A null or negative value disables "
										"that feature. If it is enabled, max-expires and min-expires "
										"will not have any effect.", "-1"},

			{String, "static-records-file", "File containing the static records to add to database at startup. "
											"Format: one 'sip_uri contact_header' by line. Example:\n"
											"<sip:contact@domain> <sip:127.0.0.1:5460>,<sip:192.168.0.1:5160>",
			 ""},
			{Integer, "static-records-timeout",
			 "Timeout in seconds after which the static records file is re-read and the contacts updated.", "600"},

			{String, "db-implementation",
			 "Implementation used for storing address of records contact uris. [redis, internal]", "internal"},
			// Redis config support
			{String, "redis-server-domain", "Domain of the redis server. ", "localhost"},
			{Integer, "redis-server-port", "Port of the redis server.", "6379"},
			{String, "redis-auth-password", "Authentication password for redis. Empty to disable.", ""},
			{Integer, "redis-server-timeout", "Timeout in milliseconds of the redis connection.", "1500"},
			{String, "redis-record-serializer", "Serialize contacts with: [C, protobuf, json, msgpack]", "protobuf"},
			{Integer, "redis-slave-check-period", "When Redis is configured in master-slave, flexisip will "
												  "periodically ask what are the slaves and the master."
												  "This is the period with which it will query the server."
												  "It will then determine whether is is connected to the master, and "
												  "if not, let go of the connection and migrate to the master."
												  "Note: This requires that all redis instances have the same "
												  "password. Otherwise the authentication will fail.",
			 "60"},
			{String, "service-route",
			 "Sequence of proxies (space-separated) where requests will be redirected through (RFC3608)", ""},
			config_item_end};
		mc->addChildrenValues(configs);

		mStats.mCountClear = mc->createStats("count-clear", "Number of cleared registrations.");
		mStats.mCountBind = mc->createStats("count-bind", "Number of registers.");
		mStats.mCountLocalActives =
			mc->createStat("count-local-registered-users", "Number of users currently registered through this server.");
	}

	virtual void onLoad(const GenericStruct *mc) {
		mUpdateOnResponse = mc->get<ConfigBoolean>("reg-on-response")->read();
		mDomains = mc->get<ConfigStringList>("reg-domains")->read();
		for (auto it = mDomains.begin(); it != mDomains.end(); ++it) {
			LOGD("Found registrar domain: %s", (*it).c_str());
		}
		mUniqueIdParams = mc->get<ConfigStringList>("unique-id-parameters")->read();
		mServiceRoute = mc->get<ConfigString>("service-route")->read();
		// replace space-separated to comma-separated since sofia-sip is expecting this way
		std::replace(mServiceRoute.begin(), mServiceRoute.end(), ' ', ',');

		int forcedExpires = mc->get<ConfigInt>("force-expires")->read();
		if(forcedExpires <= 0) {
			mMaxExpires = mc->get<ConfigInt>("max-expires")->read();
			mMinExpires = mc->get<ConfigInt>("min-expires")->read();
		} else {
			mMaxExpires = forcedExpires;
			mMinExpires = forcedExpires;
		}
		
		mStaticRecordsFile = mc->get<ConfigString>("static-records-file")->read();
		mStaticRecordsTimeout = mc->get<ConfigInt>("static-records-timeout")->read();

		if (!mStaticRecordsFile.empty()) {
			readStaticRecords(); // read static records from configuration file
			mStaticRecordsTimer = mAgent->createTimer(mStaticRecordsTimeout * 1000, &staticRoutesRereadTimerfunc, this);
		}
		mAllowDomainRegistrations = GenericManager::get()
										->getRoot()
										->get<GenericStruct>("inter-domain-connections")
										->get<ConfigBoolean>("accept-domain-registrations")
										->read();
		mAssumeUniqueDomains = GenericManager::get()
								   ->getRoot()
								   ->get<GenericStruct>("inter-domain-connections")
								   ->get<ConfigBoolean>("assume-unique-domains")
								   ->read();
		mUseGlobaleDomain = GenericManager::get()->getRoot()->get<GenericStruct>("module::Router")->get<ConfigBoolean>("use-global-domain");
		mSigaction.sa_sigaction = ModuleRegistrar::sighandler;
		mSigaction.sa_flags = SA_SIGINFO;
		sigaction(SIGUSR1, &mSigaction, NULL);
		sigaction(SIGUSR2, &mSigaction, NULL);
	}

	virtual void onUnload() {
		if (mStaticRecordsTimer) {
			su_timer_destroy(mStaticRecordsTimer);
		}
	}

	virtual void onRequest(shared_ptr<RequestSipEvent> &ev) throw (FlexisipException);

	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev) throw (FlexisipException);

	template <typename SipEventT, typename ListenerT>
	void processUpdateRequest(shared_ptr<SipEventT> &ev, const sip_t *sip);

	void idle() {
		updateLocalRegExpire();
	}

  private:
	void updateLocalRegExpire() {
		RegistrarDb *db = RegistrarDb::get(mAgent);
		db->mLocalRegExpire->removeExpiredBefore(getCurrentTime());
		mStats.mCountLocalActives->set(db->mLocalRegExpire->countActives());
	}
	bool isManagedDomain(const url_t *url) {
		return ModuleToolbox::isManagedDomain(getAgent(), mDomains, url);
	}
	string routingKey(const url_t *sipUri) {
		ostringstream oss;
		if (sipUri->url_user) {
			oss << sipUri->url_user << "@";
		}
		if(mUseGlobaleDomain) {
			oss << "merged";
		} else if (sipUri->url_host) {
			oss << sipUri->url_host;
		}
		return oss.str();
	}
	void readStaticRecords();
	bool mUpdateOnResponse;
	bool mAllowDomainRegistrations;
	list<string> mDomains;
	list<string> mUniqueIdParams;
	string mServiceRoute;
	static list<string> mPushNotifParams;
	string mRoutingParam;
	unsigned int mMaxExpires, mMinExpires;
	string mStaticRecordsFile;
	su_timer_t *mStaticRecordsTimer;
	int mStaticRecordsTimeout;
	int mStaticRecordsVersion;
	bool mAssumeUniqueDomains;
	struct sigaction mSigaction;
	static void sighandler(int signum, siginfo_t *info, void *ptr);
	static ModuleInfo<ModuleRegistrar> sInfo;
	list<shared_ptr<ResponseContext>> mRespContexes;
	bool mUseGlobaleDomain;
};

/**
 * Delta from expires header, normalized with custom rules.
 * return -1 on error
 */
static int normalizeMainDelta(const sip_expires_t *expires, const uint min, const uint max) {
	if (!expires)
		return -1;

	uint delta = expires->ex_delta;
	if (delta < min && delta > 0) {
		return min;
	} else if (delta > max) {
		return max;
	}
	return delta;
}

// Check star rules.
// If *, it must be the only contact.
// If *, associated expire must be 0.
static bool checkStarUse(const sip_contact_t *contact, int expires) {
	bool starFound = false;
	int count = 0;
	do {
		if (starFound) {
			return false;
		}

		++count;
		if ('*' == contact->m_url[0].url_scheme[0]) {
			if (count > 1 || 0 != expires)
				return false;
			starFound = true;
		}
	} while (NULL != (contact = contact->m_next));
	return true;
}

// Check an expire is present globally or in contact.
static bool checkHaveExpire(const sip_contact_t *c, int expires) {
	if (expires >= 0)
		return true; // there exist a global expire
	while (c) {
		if (!c->m_expires || atoi(c->m_expires) < 0)
			return false;
		c = c->m_next;
	}
	return true;
}

ostream &operator<<(ostream &strm, const sip_contact_t *c) {
	char b[500];
	sip_contact_e(b, sizeof(b) - 1, (msg_header_t const *)c, 0);
	strm << b;
	return strm;
}

class ResponseContext {
  public:
	const shared_ptr<RequestSipEvent> reqSipEvent;

	static shared_ptr<ResponseContext> createInTransaction(shared_ptr<RequestSipEvent> ev, int globalDelta,
														   const string &tag) {
		auto otr = ev->createOutgoingTransaction();
		auto context = make_shared<ResponseContext>(ev, globalDelta);
		otr->setProperty(tag, context);
		return context;
	}

	ResponseContext(shared_ptr<RequestSipEvent> &ev, int globalDelta)
		: reqSipEvent(ev), mHome(ev->getMsgSip()->getHome()) {
		sip_t *sip = ev->getMsgSip()->getSip();
		mFrom = sip_from_dup(mHome, sip->sip_from);
		mContacts = sip_contact_dup(mHome, sip->sip_contact);
		for (sip_contact_t *it = mContacts; it; it = it->m_next) {
			int cExpire = ExtendedContact::resolveExpire(it->m_expires, globalDelta);
			it->m_expires = su_sprintf(mHome, "%d", cExpire);
		}
		mPath = sip_path_dup(mHome, sip->sip_path);
	}

	static bool match(const shared_ptr<ResponseContext> &ctx, const char *fromtag) {
		return fromtag && strcmp(ctx->mFrom->a_tag, fromtag) == 0;
	}

	su_home_t *mHome;
	sip_from_t *mFrom;
	sip_contact_t *mContacts;
	sip_path_t *mPath;
};

static void replyPopulateEventLog(shared_ptr<SipEvent> ev, const sip_t *sip, int code, const char *reason) {
	if (sip->sip_request->rq_method == sip_method_invite) {
		shared_ptr<CallLog> calllog = ev->getEventLog<CallLog>();
		if (calllog) {
			calllog->setStatusCode(code, reason);
			calllog->setCompleted();
		}
	} else if (sip->sip_request->rq_method == sip_method_message) {
		shared_ptr<MessageLog> mlog = ev->getEventLog<MessageLog>();
		if (mlog) {
			mlog->setStatusCode(code, reason);
			mlog->setCompleted();
		}
	}
}
void ModuleRegistrar::reply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason,
							const sip_contact_t *contacts) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	replyPopulateEventLog(ev, sip, code, reason);

	if (!mServiceRoute.empty()) {
		LOGD("Setting service route to %s", mServiceRoute.c_str());
	}

	if (contacts != NULL && !mServiceRoute.empty()) {
		ev->reply(code, reason, SIPTAG_CONTACT(contacts), SIPTAG_SERVICE_ROUTE_STR(mServiceRoute.c_str()),
				  SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	} else if (contacts != NULL) {
		ev->reply(code, reason, SIPTAG_CONTACT(contacts), SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	} else if (!mServiceRoute.empty()) {
		ev->reply(code, reason, SIPTAG_SERVICE_ROUTE_STR(mServiceRoute.c_str()),
				  SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	} else {
		ev->reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	}
}

template <typename SipEventT>
static void addEventLogRecordFound(shared_ptr<SipEventT> ev, const sip_contact_t *contacts) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();

	RegistrationLog::Type type;
	if (ms->getSip()->sip_expires && ms->getSip()->sip_expires->ex_delta == 0)
		type = RegistrationLog::Unregister; // REVISIT not 100% exact.
	else
		type = RegistrationLog::Register;

	string id(contacts ? Record::extractUniqueId(contacts) : "");
	auto evlog = make_shared<RegistrationLog>(type, ms->getSip()->sip_from, id, contacts);

	if (ms->getSip()->sip_user_agent)
		evlog->setUserAgent(ms->getSip()->sip_user_agent);

	evlog->setCompleted();
	ev->setEventLog(evlog);
}

// Listener class NEED to copy the shared pointer
class OnRequestBindListener : public RegistrarDbListener {
	ModuleRegistrar *mModule;
	shared_ptr<RequestSipEvent> mEv;
	sip_from_t *mSipFrom;
	su_home_t mHome;
	sip_contact_t *mContact;
	sip_path_t *mPath;

  public:
	OnRequestBindListener(ModuleRegistrar *module, shared_ptr<RequestSipEvent> ev, const sip_from_t *sipuri = NULL,
						  sip_contact_t *contact = NULL, sip_path_t *path = NULL)
		: mModule(module), mEv(ev), mSipFrom(NULL), mContact(NULL), mPath(NULL) {
		ev->suspendProcessing();
		su_home_init(&mHome);
		if (contact)
			mContact = sip_contact_copy(&mHome, contact);
		if (path)
			mPath = sip_path_copy(&mHome, path);
		if (sipuri) {
			mSipFrom = sip_from_dup(&mHome, sipuri);
		}
	}
	~OnRequestBindListener() {
		su_home_deinit(&mHome);
	}

	void onRecordFound(Record *r) {
		const shared_ptr<MsgSip> &ms = mEv->getMsgSip();
		time_t now = getCurrentTime();
		if (r) {
			addEventLogRecordFound(mEv, mContact);
			mModule->reply(mEv, 200, "Registration successful", r->getContacts(ms->getHome(), now));

			const sip_expires_t *expires = mEv->getMsgSip()->getSip()->sip_expires;
			if (mContact && expires && expires->ex_delta > 0) {
				string uid = Record::extractUniqueId(mContact);
				string topic = mModule->routingKey(mSipFrom->a_url);
				RegistrarDb::get(mModule->getAgent())->publish(topic, uid);
			}
		} else {
			LOGE("OnRequestBindListener::onRecordFound(): Record is null");
			mModule->reply(mEv, SIP_480_TEMPORARILY_UNAVAILABLE);
		}
	}
	void onError() {
		mModule->reply(mEv, SIP_500_INTERNAL_SERVER_ERROR);
	}

	void onInvalid() {
		LOGE("OnRequestBindListener::onInvalid : 400 - Replayed CSeq");
		mModule->reply(mEv, 400, "Replayed CSeq");
	}
};

inline static bool containsNonZeroExpire(const sip_expires_t *main, const sip_contact_t *c) {
	bool nonZeroMain = main && main->ex_delta > 0;
	while (c != NULL) {
		if (c->m_expires) {
			if (atoi(c->m_expires) > 0)
				return true;
		} else if (nonZeroMain) {
			return true;
		}
		c = c->m_next;
	}
	return false;
}

class OnResponseBindListener : public RegistrarDbListener {
	ModuleRegistrar *mModule;
	shared_ptr<ResponseSipEvent> mEv;
	shared_ptr<OutgoingTransaction> mTr;
	shared_ptr<ResponseContext> mCtx;

  public:
	OnResponseBindListener(ModuleRegistrar *module, shared_ptr<ResponseSipEvent> ev, shared_ptr<OutgoingTransaction> tr,
						   shared_ptr<ResponseContext> ctx)
		: mModule(module), mEv(ev), mTr(tr), mCtx(ctx) {
		ev->suspendProcessing();
	}

	void onRecordFound(Record *r) {
		const shared_ptr<MsgSip> &ms = mEv->getMsgSip();
		time_t now = getCurrentTime();
		if (r) {
			const sip_expires_t *expires = mCtx->reqSipEvent->getMsgSip()->getSip()->sip_expires;
			if (!expires || expires->ex_delta > 0) {
				string uid = Record::extractUniqueId(mCtx->mContacts);
				string topic = mModule->routingKey(mCtx->mFrom->a_url);
				RegistrarDb::get(mModule->getAgent())->publish(topic, uid);
			}
			const sip_contact_t *dbContacts = r->getContacts(ms->getHome(), now);
			// Replace received contacts by our ones
			auto &reMs = mEv->getMsgSip();
			reMs->getSip()->sip_contact = sip_contact_dup(reMs->getHome(), dbContacts);
			addEventLogRecordFound(mEv, dbContacts);
			mModule->getAgent()->injectResponseEvent(mEv);
		} else {
			LOGE("OnResponseBindListener::onRecordFound(): Record is null");
			mCtx->reqSipEvent->reply(SIP_480_TEMPORARILY_UNAVAILABLE, TAG_END());
			mEv->terminateProcessing();
		}
	}
	void onError() {
		LOGE("OnResponseBindListener::onError(): 500");
		mCtx->reqSipEvent->reply(SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		mEv->terminateProcessing();
	}

	void onInvalid() {
		LOGE("OnResponseBindListener::onInvalid: 400 - Replayed CSeq");
		mCtx->reqSipEvent->reply(400, "Replayed CSeq", TAG_END());
		mEv->terminateProcessing();
	}
};

template <typename SipEventT, typename ListenerT>
void ModuleRegistrar::processUpdateRequest(shared_ptr<SipEventT> &ev, const sip_t *sip) {
	const sip_expires_t *expires = sip->sip_expires;
	const int maindelta = normalizeMainDelta(expires, mMinExpires, mMaxExpires);
	if ('*' == sip->sip_contact->m_url[0].url_scheme[0]) {
		auto listener = make_shared<ListenerT>(this, ev);
		mStats.mCountClear->incrStart();
		LOGD("Clearing bindings");
		listener->addStatCounter(mStats.mCountClear->finish);
		RegistrarDb::get(mAgent)->clear(sip, listener);
		return;
	} else {
		auto listener = make_shared<ListenerT>(this, ev, sip->sip_from, sip->sip_contact);
		mStats.mCountBind->incrStart();
		LOGD("Updating binding");
		listener->addStatCounter(mStats.mCountBind->finish);
		RegistrarDb::get(mAgent)->bind(sip, mAgent->getPreferredRoute().c_str(), maindelta, false, listener);
		return;
	}
}

void ModuleRegistrar::onRequest(shared_ptr<RequestSipEvent> &ev) throw(FlexisipException) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	// Only handles registers
	if (sip->sip_request->rq_method != sip_method_register)
		return;

	// from managed domains
	url_t *sipurl = sip->sip_from->a_url;
	if (!sipurl->url_host || !isManagedDomain(sipurl))
		return;

	// Handle fetching
	if (sip->sip_contact == NULL) {
		LOGD("No sip contact, it is a fetch only request for %s.", url_as_string(ms->getHome(), sipurl));
		auto listener = make_shared<OnRequestBindListener>(this, ev);
		RegistrarDb::get(mAgent)->fetch(sipurl, listener);
		return;
	}

	// Reject malformed registrations
	const sip_expires_t *expires = sip->sip_expires;
	const int maindelta = normalizeMainDelta(expires, mMinExpires, mMaxExpires);
	if (!checkHaveExpire(sip->sip_contact, maindelta)) {
		SLOGD << "No global or local expire found in at least one contact";
		reply(ev, 400, "Invalid Request");
		return;
	}
	if (!checkStarUse(sip->sip_contact, maindelta)) {
		LOGD("The star rules are not respected.");
		reply(ev, 400, "Invalid Request");
		return;
	}

	// Use path as a contact route in all cases
	addPathHeader(getAgent(), ev, ev->getIncomingTport().get());

	// domain registration case, does nothing for the moment
	if (sipurl->url_user == NULL && !mAllowDomainRegistrations) {
		LOGE("Not accepting domain registration");
		reply(ev, 403, "Domain registration forbidden", NULL);
		return;
	}

	// Handle modifications
	if (!mUpdateOnResponse) {
		if ('*' == sip->sip_contact->m_url[0].url_scheme[0]) {
			auto listener = make_shared<OnRequestBindListener>(this, ev);
			mStats.mCountClear->incrStart();
			LOGD("Clearing bindings");
			listener->addStatCounter(mStats.mCountClear->finish);
			RegistrarDb::get(mAgent)->clear(sip, listener);
			return;
		} else {
			if (sipurl->url_user == NULL && mAssumeUniqueDomains) {
				/*first clear to make sure that there is only one record*/
				RegistrarDb::get(mAgent)->clear(sip, make_shared<FakeFetchListener>());
			}
			auto listener =
				make_shared<OnRequestBindListener>(this, ev, sip->sip_from, sip->sip_contact, sip->sip_path);
			mStats.mCountBind->incrStart();
			LOGD("Updating binding");
			listener->addStatCounter(mStats.mCountBind->finish);
			RegistrarDb::get(mAgent)->bind(sip, maindelta, false, listener);
			return;
		}
	} else {
		// Go stateful to stop retransmissions
		ev->createIncomingTransaction();
		ev->reply(SIP_100_TRYING, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());

		auto context = ResponseContext::createInTransaction(ev, maindelta, getModuleName());
		// Contact route inserter should masquerade contact using domain
		SLOGD << "Contacts :" << context->mContacts;
		// Store a reference to the ResponseContext to prevent its destruction
		mRespContexes.push_back(context);

		// Cleaner contacts
		su_home_t *home = ev->getMsgSip()->getHome();
		removeParamsFromContacts(home, sip->sip_contact, mUniqueIdParams);
		removeParamsFromContacts(home, sip->sip_contact, sPushNotifParams);
		SLOGD << "Removed instance and push params: \n" << sip->sip_contact;

		if (sip->sip_path) {
			sip->sip_path = NULL;
			SLOGD << "Removed paths";
		}
		// Let the modified initial event flow (will not be forked).
	}
}

void ModuleRegistrar::onResponse(shared_ptr<ResponseSipEvent> &ev) throw(FlexisipException) {
	if (!mUpdateOnResponse)
		return;
	const shared_ptr<MsgSip> &reMs = ev->getMsgSip();
	sip_t *reSip = reMs->getSip();

	// Only handle response to registers
	if (reSip->sip_cseq->cs_method != sip_method_register)
		return;
	// Handle db update on response
	const url_t *reSipurl = reSip->sip_from->a_url;
	if (!reSipurl->url_host || !isManagedDomain(reSipurl))
		return;

	auto transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction == NULL) {
		/*not a response we want to manage*/
		return;
	}

	auto context = transaction->getProperty<ResponseContext>(getModuleName());
	if (!context) {
		LOGD("No response context found");
		return;
	}

	if (reSip->sip_status->st_status == 200) {
		// Warning: here we give the RESPONSE sip message
		const sip_expires_t *expires = reSip->sip_expires;
		const int maindelta = normalizeMainDelta(expires, mMinExpires, mMaxExpires);
		auto listener = make_shared<OnResponseBindListener>(this, ev, transaction, context);

		// Rewrite contacts in received msg (avoid reworking registrardb API)
		reSip->sip_contact = context->mContacts;
		reSip->sip_path = context->mPath;

		if ('*' == reSip->sip_contact->m_url[0].url_scheme[0]) {
			mStats.mCountClear->incrStart();
			LOGD("Clearing bindings");
			listener->addStatCounter(mStats.mCountClear->finish);
			RegistrarDb::get(mAgent)->clear(reSip, listener);
		} else {
			mStats.mCountBind->incrStart();
			LOGD("Updating binding");
			listener->addStatCounter(mStats.mCountBind->finish);
			RegistrarDb::get(mAgent)->bind(reSip, maindelta, false, listener);
		}
	}
	if (reSip->sip_status->st_status >= 200) {
		/*for all final responses, drop the context anyway*/
		mRespContexes.remove(context);
	}
}

/* Section for static records */

// Listener class NEED to copy the shared pointer
class OnStaticBindListener : public RegistrarDbListener {
	friend class ModuleRegistrar;
	SofiaAutoHome mHome;
	string mContact;
	string mFrom;

  public:
	OnStaticBindListener(const url_t *from, const sip_contact_t *ct) {
		mFrom = url_as_string(mHome.home(), from);
		mContact = url_as_string(mHome.home(), ct->m_url);
	}
	void onRecordFound(Record *r) {
		LOGD("Static route added for %s: %s", mFrom.c_str(), mContact.c_str());
	}
	void onError() {
		LOGE("Can't add static route for %s", mFrom.c_str());
	}
	void onInvalid() {
		LOGE("OnStaticBindListener onInvalid");
	}
};

void ModuleRegistrar::readStaticRecords() {
	if (mStaticRecordsFile.empty())
		return;
	LOGD("Reading static records file");

	su_home_t home;

	stringstream ss;
	ss.exceptions(ifstream::failbit | ifstream::badbit);

	string line;
	string from;
	string contact_header;

	ifstream file;
	file.open(mStaticRecordsFile);
	if (file.is_open()) {
		su_home_init(&home);
		sip_path_t *path = sip_path_format(&home, "%s", getAgent()->getPreferredRoute().c_str());
		mStaticRecordsVersion++;
		while (file.good() && getline(file, line).good()) {
			size_t i;
			bool is_a_comment = false;
			for (i = 0; i < line.size(); ++i) {
				// skip spaces or comments
				if (isblank(line[i]))
					continue;
				if (line[i] == '#')
					is_a_comment = true;
				else
					break;
			}
			if (is_a_comment)
				continue;
			if (i == line.size())
				continue; // blank line
			size_t cttpos = line.find_first_of(' ', i);
			if (cttpos != string::npos && cttpos < line.size()) {
				// Read uri
				from = line.substr(0, cttpos);

				// Read contacts
				contact_header = line.substr(cttpos + 1, line.length() - cttpos + 1);

				// Create
				sip_contact_t *url = sip_contact_make(&home, from.c_str());
				sip_contact_t *contact = sip_contact_make(&home, contact_header.c_str());
				int expire = mStaticRecordsTimeout + 5; // 5s to avoid race conditions

				if (url != NULL) {
					while (contact != NULL) {
						sip_contact_t single = *contact;
						single.m_next = NULL;
						auto listener = make_shared<OnStaticBindListener>(url->m_url, &single);
						bool alias = isManagedDomain(contact->m_url);
						const char *fakeCallId = su_sprintf(&home, "static-record-v%x", su_random());

						RegistrarDb::BindParameters params(RegistrarDb::BindParameters::SipParams(
															   url->m_url /*from*/, &single, fakeCallId, 0, path, NULL),
														   expire, alias);
						params.version = mStaticRecordsVersion;
						/*if no user part is given, consider it as to be used as a route, that is not changing the
						 * request uri but instead prepend a route*/
						params.usedAsRoute = (single.m_url->url_user == NULL);
						RegistrarDb::get(mAgent)->bind(params, listener);
						contact = contact->m_next;
					}
				}
				continue;
			}
			LOGW("Incorrect line format: %s", line.c_str());
		}
		su_home_deinit(&home);
	} else {
		LOGE("Can't open file %s", mStaticRecordsFile.c_str());
	}
}

void ModuleRegistrar::sighandler(int signum, siginfo_t *info, void *ptr) {
	if (signum == SIGUSR1) {
		LOGI("Received signal triggering static records file re-read");
		sRegistrarInstanceForSigAction->readStaticRecords();
	} else if (signum == SIGUSR2) {
		LOGI("Received signal triggering fake fetch");
		su_home_t home;
		su_home_init(&home);
		url_t *url = url_make(&home, "sip:contact@domain");

		auto listener = make_shared<FakeFetchListener>();
		RegistrarDb::get(sRegistrarInstanceForSigAction->getAgent())->fetch(url, listener, false);
	}
}

ModuleInfo<ModuleRegistrar> ModuleRegistrar::sInfo(
	"Registrar", "The ModuleRegistrar module accepts REGISTERs for domains it manages, and store the address of record "
				 "in order to allow routing requests destinated to the client who registered.",
	ModuleInfoBase::ModuleOid::Registrar);
