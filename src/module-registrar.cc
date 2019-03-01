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

#include <flexisip/module-registrar.hh>
#include <flexisip/logmanager.hh>

#include <fstream>
#include <sstream>
#include <ostream>
#include <string>
#include <csignal>
#include <functional>
#include <algorithm>

using namespace std;
using namespace flexisip;

static ModuleRegistrar *sRegistrarInstanceForSigAction = nullptr;

template <typename SipEventT>
static void addEventLogRecordFound(shared_ptr<SipEventT> ev, const sip_contact_t *contacts) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	string id(contacts ? Record::extractUniqueId(contacts) : "");
	auto evlog = make_shared<RegistrationLog>(ms->getSip(), contacts);

	evlog->setStatusCode(200, "Ok");
	evlog->setCompleted();
	ev->setEventLog(evlog);
}

static void _onContactUpdated(ModuleRegistrar *module, tport_t *new_tport, const shared_ptr<ExtendedContact> &ec) {
	SofiaAutoHome home;
	tp_name_t name = {0, 0, 0, 0, 0, 0};
	tport_t *old_tport;

	if (module->getAgent() != nullptr && ec->mPath.size() == 1) {
		if (tport_name_by_url(home.home(), &name, (url_string_t *)ec->mSipContact->m_url) == 0) {
			old_tport = tport_by_name(nta_agent_tports(module->getSofiaAgent()), &name);

			// Not the same tport but had the same ConnId
			if (old_tport && new_tport != old_tport &&
				(tport_get_user_data(old_tport) == nullptr || ec->mConnId == (uintptr_t)tport_get_user_data(old_tport))) {
				SLOGD << "Removing old tport for sip uri " << ExtendedContact::urlToString(ec->mSipContact->m_url);
				// 0 close incoming data, 1 close outgoing data, 2 both
				tport_shutdown(old_tport, 2);
			}
		} else {
			SLOGE << "ContactUpdated: tport_name_by_url() failed for sip uri "
				<< ExtendedContact::urlToString(ec->mSipContact->m_url);
		}
	}
}

OnRequestBindListener::OnRequestBindListener(ModuleRegistrar *module, std::shared_ptr<RequestSipEvent> ev, const sip_from_t *sipuri,
						sip_contact_t *contact, sip_path_t *path)
	: mModule(module), mEv(ev), mSipFrom(nullptr), mContact(nullptr), mPath(nullptr) {
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
OnRequestBindListener::~OnRequestBindListener() {
	su_home_deinit(&mHome);
}

void OnRequestBindListener::onContactUpdated(const std::shared_ptr<ExtendedContact> &ec) {
	_onContactUpdated(this->mModule, this->mEv->getIncomingTport().get(), ec);
}

void OnRequestBindListener::onRecordFound(const shared_ptr<Record> &r) {
	const shared_ptr<MsgSip> &ms = mEv->getMsgSip();
	time_t now = getCurrentTime();
	if (r) {
		addEventLogRecordFound(mEv, mContact);
		mModule->reply(mEv, 200, "Registration successful", r->getContacts(ms->getHome(), now));

		if (mContact) {
			string uid = Record::extractUniqueId(mContact);
			string topic = mModule->routingKey(mSipFrom->a_url);
			RegistrarDb::get()->publish(topic, uid);
		}
	} else {
		LOGE("OnRequestBindListener::onRecordFound(): Record is null");
		mModule->reply(mEv, SIP_500_INTERNAL_SERVER_ERROR);
	}
}
void OnRequestBindListener::onError() {
	mModule->reply(mEv, SIP_500_INTERNAL_SERVER_ERROR);
}

void OnRequestBindListener::onInvalid() {
	LOGE("OnRequestBindListener::onInvalid : 400 - Replayed CSeq");
	mModule->reply(mEv, 400, "Replayed CSeq");
}

OnResponseBindListener::OnResponseBindListener(ModuleRegistrar *module, shared_ptr<ResponseSipEvent> ev, shared_ptr<OutgoingTransaction> tr,
						shared_ptr<ResponseContext> ctx)
	: mModule(module), mEv(ev), mTr(tr), mCtx(ctx) {
	ev->suspendProcessing();
}

void OnResponseBindListener::onRecordFound(const shared_ptr<Record> &r) {
	const shared_ptr<MsgSip> &ms = mEv->getMsgSip();
	time_t now = getCurrentTime();
	if (r) {
		string uid = Record::extractUniqueId(mCtx->mContacts);
		string topic = mModule->routingKey(mCtx->mFrom->a_url);
		RegistrarDb::get()->publish(topic, uid);

		const sip_contact_t *dbContacts = r->getContacts(ms->getHome(), now);
		// Replace received contacts by our ones
		auto &reMs = mEv->getMsgSip();
		reMs->getSip()->sip_contact = sip_contact_dup(reMs->getHome(), dbContacts);
		addEventLogRecordFound(mEv, dbContacts);
		mModule->getAgent()->injectResponseEvent(mEv);
	} else {
		LOGE("OnResponseBindListener::onRecordFound(): Record is null");
		mCtx->reqSipEvent->reply(SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		mEv->terminateProcessing();
	}
}
void OnResponseBindListener::onError() {
	LOGE("OnResponseBindListener::onError(): 500");
	mCtx->reqSipEvent->reply(SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
	mEv->terminateProcessing();
}

void OnResponseBindListener::onInvalid() {
	LOGE("OnResponseBindListener::onInvalid: 400 - Replayed CSeq");
	mCtx->reqSipEvent->reply(400, "Replayed CSeq", TAG_END());
	mEv->terminateProcessing();
}

void OnResponseBindListener::onContactUpdated(const shared_ptr<ExtendedContact> &ec) {
	_onContactUpdated(this->mModule, this->mCtx->reqSipEvent->getIncomingTport().get(), ec);
}

OnStaticBindListener::OnStaticBindListener(const url_t *from, const sip_contact_t *ct) {
	mFrom = url_as_string(mHome.home(), from);
	mContact = url_as_string(mHome.home(), ct->m_url);
}
void OnStaticBindListener::onRecordFound(const shared_ptr<Record> &r) {
	LOGD("Static route added for %s: %s", mFrom.c_str(), mContact.c_str());
}
void OnStaticBindListener::onError() {
	LOGE("Can't add static route for %s", mFrom.c_str());
}
void OnStaticBindListener::onInvalid() {
	LOGE("OnStaticBindListener onInvalid");
}
void OnStaticBindListener::onContactUpdated(const shared_ptr<ExtendedContact> &ec) {
}

FakeFetchListener::FakeFetchListener() {
}

void FakeFetchListener::onRecordFound(const shared_ptr<Record> &r) {
	if (r != nullptr) {
		SLOGD << r;
	} else {
		LOGD("No record found");
	}
}
void FakeFetchListener::onError() {
}

void FakeFetchListener::onInvalid() {
	LOGD("FakeFetchListener: onInvalid");
}

void FakeFetchListener::onContactUpdated(const shared_ptr<ExtendedContact> &ec) {
}

shared_ptr<ResponseContext> ResponseContext::createInTransaction(shared_ptr<RequestSipEvent> ev, int globalDelta,
														const string &tag) {
	auto otr = ev->createOutgoingTransaction();
	auto context = make_shared<ResponseContext>(ev, globalDelta);
	otr->setProperty(tag, context);
	return context;
}

ResponseContext::ResponseContext(shared_ptr<RequestSipEvent> &ev, int globalDelta)
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

bool ResponseContext::match(const shared_ptr<ResponseContext> &ctx, const char *fromtag) {
	return fromtag && strcmp(ctx->mFrom->a_tag, fromtag) == 0;
}

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
	} while (nullptr != (contact = contact->m_next));
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

static void staticRoutesRereadTimerfunc(su_root_magic_t *magic, su_timer_t *t, void *data) {
	ModuleRegistrar *r = (ModuleRegistrar *)data;
	r->readStaticRecords();
}

ModuleRegistrar::ModuleRegistrar(Agent *ag) : Module(ag), mStaticRecordsTimer(nullptr) {
	sRegistrarInstanceForSigAction = this;
	memset(&mSigaction, 0, sizeof(mSigaction));
	mStaticRecordsVersion = 0;
}

void ModuleRegistrar::onDeclare(GenericStruct *mc) {
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
			"Implementation used for storing address of records contact uris. Two backends are available:\n"
			"- redis : contacts are stored in a redis database, which allows persistent and shared storage accross multiple flexisip nodes\n"
			"- internal : contacts are stored in RAM. Of course, if flexisip is restarted, all contacts are lost until client update their"
			" registration.\n"
			"The redis backend is recommended, the internal being more adapted to very small deployments.", "internal"},
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
		{String, "name-message-expires", "The name used for the expire time of forking message", "message-expires"},
		{Integer, "register-expire-randomizer-max", "Maximum percentage of the REGISTER expire to randomly remove, 0 to disable", "0"},
		config_item_end};
	mc->addChildrenValues(configs);

	mStats.mCountClear = mc->createStats("count-clear", "Number of cleared registrations.");
	mStats.mCountBind = mc->createStats("count-bind", "Number of registers.");
	mStats.mCountLocalActives = mc->createStat("count-local-registered-users", "Number of users currently registered through this server.");
}

void ModuleRegistrar::onLoad(const GenericStruct *mc) {
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

	mExpireRandomizer = mc->get<ConfigInt>("register-expire-randomizer-max")->read();

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
	mUseGlobalDomain = GenericManager::get()->getRoot()->get<GenericStruct>("module::Router")->get<ConfigBoolean>("use-global-domain")->read();
	mSigaction.sa_sigaction = ModuleRegistrar::sighandler;
	mSigaction.sa_flags = SA_SIGINFO;
	sigaction(SIGUSR1, &mSigaction, nullptr);
	sigaction(SIGUSR2, &mSigaction, nullptr);

	mParamsToRemove = GenericManager::get()->getRoot()->get<GenericStruct>("module::Forward")->get<ConfigStringList>("params-to-remove")->read();
}

void ModuleRegistrar::onUnload() {
	if (mStaticRecordsTimer) {
		su_timer_destroy(mStaticRecordsTimer);
	}
}

void ModuleRegistrar::idle() {
	updateLocalRegExpire();
}

void ModuleRegistrar::updateLocalRegExpire() {
	RegistrarDb::get()->mLocalRegExpire->removeExpiredBefore(getCurrentTime());
	mStats.mCountLocalActives->set(RegistrarDb::get()->mLocalRegExpire->countActives());
}

bool ModuleRegistrar::isManagedDomain(const url_t *url) {
	return ModuleToolbox::isManagedDomain(getAgent(), mDomains, url);
}

string ModuleRegistrar::routingKey(const url_t *sipUri) {
	return Record::defineKeyFromUrl(sipUri);
}

void ModuleRegistrar::reply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason,
							const sip_contact_t *contacts) {
	sip_contact_t *modified_contacts = nullptr;
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	int expire = sip->sip_expires ? sip->sip_expires->ex_delta : 0;
	string expire_str = std::to_string(expire);

	replyPopulateEventLog(ev, sip, code, reason);

	if (!mServiceRoute.empty()) {
		LOGD("Setting service route to %s", mServiceRoute.c_str());
	}

	if (contacts) {
		modified_contacts = sip_contact_dup(ev->getHome(), contacts);
	}
	// This ensures not all REGISTERs arrive at the same time on the flexisip
	if (sip->sip_request->rq_method == sip_method_register && code == 200 && mExpireRandomizer > 0 && expire > 0) {
			expire = (int) expire - (expire * su_randint(0, mExpireRandomizer) / 100);
			expire_str = std::to_string(expire);
			if (contacts) {
				su_home_t *home = ev->getHome();
				msg_header_replace_param(home, (msg_common_t *)modified_contacts, su_sprintf(home, "expires=%i", expire));
			}
	}

	for (sip_contact_t *contact = modified_contacts; contact!=nullptr ; contact=contact->m_next) {
		if(sip->sip_request->rq_method == sip_method_register && code == 200 && contact) {
			if (url_has_param(contact->m_url, "gr")) {
				string gruu;
				char *buffer = new char[255];
				isize_t result = url_param(contact->m_url->url_params, "gr", buffer, 255);
				if (result > 0) {
					su_home_t *home = ev->getHome();
					stringstream stream;
					gruu = string(buffer);
					contact->m_url->url_params = url_strip_param_string((char *)contact->m_url->url_params,"gr");
					stream << "\"" << url_as_string(home, sip->sip_from->a_url) << ";gr=" << gruu << "\"";
					msg_header_replace_param(home, (msg_common_t *) contact, su_sprintf(home, "pub-gruu=%s", stream.str().c_str()));
				}
				delete[] buffer;
			}
			if (url_has_param(contact->m_url, "fs-conn-id")) {
				contact->m_url->url_params = url_strip_param_string((char *)contact->m_url->url_params,"fs-conn-id");
			}
		}
	}
	if (modified_contacts && !mServiceRoute.empty()) {
		if (expire > 0) {
			ev->reply(code, reason, SIPTAG_CONTACT(modified_contacts), SIPTAG_SERVICE_ROUTE_STR(mServiceRoute.c_str()),
					SIPTAG_SERVER_STR(getAgent()->getServerString()), SIPTAG_EXPIRES_STR(expire_str.c_str()), TAG_END());
		} else {
			ev->reply(code, reason, SIPTAG_CONTACT(modified_contacts), SIPTAG_SERVICE_ROUTE_STR(mServiceRoute.c_str()),
				  SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		}
	} else if (modified_contacts) {
		if (expire > 0) {
			ev->reply(code, reason, SIPTAG_CONTACT(modified_contacts), SIPTAG_SERVER_STR(getAgent()->getServerString()),
					SIPTAG_EXPIRES_STR(expire_str.c_str()), TAG_END());
		} else {
			ev->reply(code, reason, SIPTAG_CONTACT(modified_contacts), SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		}
	} else if (!mServiceRoute.empty()) {
		if (expire > 0) {
			ev->reply(code, reason, SIPTAG_SERVICE_ROUTE_STR(mServiceRoute.c_str()),
					SIPTAG_SERVER_STR(getAgent()->getServerString()), SIPTAG_EXPIRES_STR(expire_str.c_str()), TAG_END());
		} else {
			ev->reply(code, reason, SIPTAG_SERVICE_ROUTE_STR(mServiceRoute.c_str()),
					SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		}
	} else {
		if (expire > 0) {
			ev->reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), SIPTAG_EXPIRES_STR(expire_str.c_str()),
					TAG_END());
		} else {
			ev->reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		}
	}
}

inline static bool containsNonZeroExpire(const sip_expires_t *main, const sip_contact_t *c) {
	bool nonZeroMain = main && main->ex_delta > 0;
	while (c != nullptr) {
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

template <typename SipEventT, typename ListenerT>
void ModuleRegistrar::processUpdateRequest(shared_ptr<SipEventT> &ev, const sip_t *sip) {
	const sip_expires_t *expires = sip->sip_expires;
	const int maindelta = normalizeMainDelta(expires, mMinExpires, mMaxExpires);
	if ('*' == sip->sip_contact->m_url[0].url_scheme[0]) {
		auto listener = make_shared<ListenerT>(this, ev);
		mStats.mCountClear->incrStart();
		LOGD("Clearing bindings");
		listener->addStatCounter(mStats.mCountClear->finish);
		RegistrarDb::get()->clear(sip, listener);
		return;
	} else {
		auto listener = make_shared<ListenerT>(this, ev, sip->sip_from, sip->sip_contact);
		mStats.mCountBind->incrStart();
		LOGD("Updating binding");
		listener->addStatCounter(mStats.mCountBind->finish);
		RegistrarDb::get()->bind(sip, maindelta, false, 0, listener);
		return;
	}
}

void ModuleRegistrar::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	if (sip->sip_request->rq_method != sip_method_register)
		return;

	// from managed domains
	url_t *sipurl = sip->sip_from->a_url;
	if (!sipurl->url_host || !isManagedDomain(sipurl))
		return;

	// Handle fetching
	if (sip->sip_contact == nullptr) {
		LOGD("No sip contact, it is a fetch only request for %s.", url_as_string(ms->getHome(), sipurl));
		auto listener = make_shared<OnRequestBindListener>(this, ev);
		RegistrarDb::get()->fetch(sipurl, listener);
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
	if (sip->sip_contact->m_url[0].url_scheme == nullptr){
		reply(ev, 400, "Invalid contact");
		return;
	}
	if (!checkStarUse(sip->sip_contact, maindelta)) {
		LOGD("The star rules are not respected.");
		reply(ev, 400, "Invalid Request");
		return;
	}
	
	
	// Use path as a contact route in all cases
	// Preferred Route is only set if cluster mode is enabled
	if (!getAgent()->getPreferredRoute().empty()) {
		sip_path_t *path = sip_path_format(ms->getHome(), "<%s>", getAgent()->getPreferredRoute().c_str()); //format a Path
		msg_t *msg = ev->getMsgSip()->getMsg();
		if (!prependNewRoutable(msg, sip, sip->sip_path, path)) {
			SLOGD << "Identical path already existing: " << getAgent()->getPreferredRoute();
		}
	} else {
		addPathHeader(getAgent(), ev, ev->getIncomingTport().get());
	}

	// Init conn id in tport
	{
		ostringstream os;
		uintptr_t connId = (tport_get_user_data(ev->getIncomingTport().get())) ?
			reinterpret_cast<uintptr_t>(tport_get_user_data(ev->getIncomingTport().get())) : static_cast<uintptr_t>(su_random64());
		os << "fs-conn-id=" << hex << connId;
		url_param_add(ms->getHome(), sip->sip_contact->m_url, os.str().c_str());
		tport_set_user_data(ev->getIncomingTport().get(), reinterpret_cast<void*>(connId));
	}

	// domain registration case, does nothing for the moment
	if (sipurl->url_user == nullptr && !mAllowDomainRegistrations) {
		LOGE("Not accepting domain registration");
		SLOGUE << "Not accepting domain registration:  " << url_as_string(ms->getHome(), sipurl);
		reply(ev, 403, "Domain registration forbidden", nullptr);
		return;
	}

	// Handle modifications
	if (!mUpdateOnResponse) {
		if ('*' == sip->sip_contact->m_url[0].url_scheme[0]) {
			auto listener = make_shared<OnRequestBindListener>(this, ev);
			mStats.mCountClear->incrStart();
			LOGD("Clearing bindings");
			listener->addStatCounter(mStats.mCountClear->finish);
			RegistrarDb::get()->clear(sip, listener);
			return;
		} else {
			if (sipurl->url_user == nullptr && mAssumeUniqueDomains) {
				/*first clear to make sure that there is only one record*/
				RegistrarDb::get()->clear(sip, make_shared<FakeFetchListener>());
			}
			BindingParameters parameter;
			auto listener =
				make_shared<OnRequestBindListener>(this, ev, sip->sip_from, sip->sip_contact, sip->sip_path);
			mStats.mCountBind->incrStart();
			LOGD("Updating binding");
			listener->addStatCounter(mStats.mCountBind->finish);
			parameter.alias = false;
			parameter.globalExpire = maindelta;
			parameter.version = 0;
			RegistrarDb::get()->bind(sip, parameter, listener);
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
		removeParamsFromContacts(home, sip->sip_contact, mParamsToRemove);
		SLOGD << "Removed instance and push params: \n" << sip->sip_contact;

		if (sip->sip_path) {
			sip->sip_path = nullptr;
			SLOGD << "Removed paths";
		}
		// Let the modified initial event flow (will not be forked).
	}
}

void ModuleRegistrar::onResponse(shared_ptr<ResponseSipEvent> &ev) {
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
	if (transaction == nullptr) {
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
		const sip_expires_t *expires;
		shared_ptr<MsgSip> request = transaction->getRequestMsg();
		if (request) {
			expires = request->getSip()->sip_expires;
		} else {
			expires = reSip->sip_expires;
		}
		const int maindelta = normalizeMainDelta(expires, mMinExpires, mMaxExpires);
		auto listener = make_shared<OnResponseBindListener>(this, ev, transaction, context);

		// Rewrite contacts in received msg (avoid reworking registrardb API)
		reSip->sip_contact = context->mContacts;
		reSip->sip_path = context->mPath;

		if ('*' == reSip->sip_contact->m_url[0].url_scheme[0]) {
			mStats.mCountClear->incrStart();
			LOGD("Clearing bindings");
			listener->addStatCounter(mStats.mCountClear->finish);
			RegistrarDb::get()->clear(reSip, listener);
		} else {
			BindingParameters parameter;
			mStats.mCountBind->incrStart();
			LOGD("Updating binding");
			parameter.alias = false;
			parameter.globalExpire = maindelta;
			parameter.version = 0;
			listener->addStatCounter(mStats.mCountBind->finish);
			RegistrarDb::get()->bind(reSip, parameter, listener);
		}
	}
	if (reSip->sip_status->st_status >= 200) {
		/*for all final responses, drop the context anyway*/
		mRespContexes.remove(context);
	}
}

void ModuleRegistrar::readStaticRecords() {
	if (mStaticRecordsFile.empty()) return;
	LOGD("Reading static records file");

	SofiaAutoHome home;

	stringstream ss;
	ss.exceptions(ifstream::failbit | ifstream::badbit);

	string line;
	string from;
	string contact_header;

	ifstream file;
	file.open(mStaticRecordsFile);
	if (file.is_open()) {
		string path = getAgent()->getPreferredRoute();
		mStaticRecordsVersion++;
		while (file.good() && !file.eof()) {
			getline(file, line);
			size_t i;
			bool is_a_comment = false;
			for (i = 0; i < line.size(); ++i) {
				// skip spaces or comments
				if (isblank(line[i])) continue;
				if (line[i] == '#') {
					is_a_comment = true;
				} else {
					break;
				}
			}
			if (is_a_comment) continue;
			if (i == line.size()) continue; // blank line
			size_t cttpos = line.find_first_of(' ', i);
			if (cttpos != string::npos && cttpos < line.size()) {

				// Read uri
				from = line.substr(0, cttpos);

				// Read contacts
				contact_header = line.substr(cttpos + 1, line.length() - cttpos + 1);

				// Create
				sip_contact_t *url = sip_contact_make(home.home(), from.c_str());
				sip_contact_t *contact = sip_contact_make(home.home(), contact_header.c_str());
				int expire = mStaticRecordsTimeout + 5; // 5s to avoid race conditions

				if (!url || !contact) {
					LOGF("Static records line %s doesn't respect the expected format: <identity> <identity>,<identity>", line.c_str());
					continue;
				}

				while (contact) {
					BindingParameters parameter;
					shared_ptr<OnStaticBindListener> listener;
					string fakeCallId = "static-record-v" + to_string(su_random());
					bool alias = isManagedDomain(contact->m_url);
					sip_contact_t *sipContact = sip_contact_dup(home.home(), contact);

					sipContact->m_next = nullptr;
					listener = make_shared<OnStaticBindListener>(url->m_url, contact);

					parameter.callId = fakeCallId;
					parameter.path = path;
					parameter.globalExpire = expire;
					parameter.alias = alias;
					parameter.version = mStaticRecordsVersion;

					RegistrarDb::get()->bind(url->m_url, sipContact, parameter, listener);
					contact = contact->m_next;
				}
				continue;
			}
			LOGW("Incorrect line format: %s", line.c_str());
		}
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
		RegistrarDb::get()->fetch(url, listener, false);
	}
}

ModuleInfo<ModuleRegistrar> ModuleRegistrar::sInfo(
	"Registrar",
	"The ModuleRegistrar module accepts REGISTERs for domains it manages, and store the address of record "
	"in order to allow routing requests destinated to the client who registered.",
	{ "Presence" },
	ModuleInfoBase::ModuleOid::Registrar
);
