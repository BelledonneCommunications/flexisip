/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/module-registrar.hh"

#include <algorithm>

#include <csignal>
#include <fstream>
#include <functional>
#include <ostream>
#include <regex>

#include "flexisip/logmanager.hh"
#include "flexisip/signal-handling/sofia-driven-signal-handler.hh"

#include "agent.hh"
#include "domain-registrations.hh"
#include "eventlogs/events/eventlogs.hh"
#include "module-toolbox.hh"
#include "nat/nat-traversal-strategy.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"
#include "transaction/outgoing-agent.hh"
#include "transaction/outgoing-transaction.hh"
#include "utils/uri-utils.hh"

using namespace std;
using namespace flexisip;

template <typename SipEventT>
static void addEventLogRecordFound(shared_ptr<SipEventT> ev, shared_ptr<Record> r, const sip_contact_t* contacts) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	string id(contacts ? r->extractUniqueId(contacts) : "");
	auto evLog = make_shared<RegistrationLog>(ms->getSip(), contacts);

	evLog->setStatusCode(200, "Ok");
	evLog->setCompleted();
	ev->setEventLog(evLog);
}

static void _onContactUpdated(ModuleRegistrar* module, tport_t* new_tport, const shared_ptr<ExtendedContact>& ec) {
	sofiasip::Home home;
	tp_name_t name = {0, 0, 0, 0, 0, 0};
	tport_t* old_tport;

	if (module->getAgent() != nullptr && ec->mPath.size() == 1) {
		if (tport_name_by_url(home.home(), &name, (url_string_t*)ec->mSipContact->m_url) == 0) {
			old_tport = tport_by_name(nta_agent_tports(module->getSofiaAgent()), &name);

			// Not the same tport but had the same ConnId
			if (old_tport && new_tport != old_tport &&
			    (tport_get_user_data(old_tport) == nullptr ||
			     ec->mConnId == (uintptr_t)tport_get_user_data(old_tport))) {
				SLOGD << "Removing old tport for sip uri " << ExtendedContact::urlToString(ec->mSipContact->m_url);
				// 0 close incoming data, 1 close outgoing data, 2 both
				tport_shutdown(old_tport, 2);
			}
		} else if (UriUtils::isIpAddress(ec->mSipContact->m_url->url_host)) {
			SLOGE << "ContactUpdated: tport_name_by_url() failed for sip uri "
			      << ExtendedContact::urlToString(ec->mSipContact->m_url);
		} else {
			SLOGD << "ContactUpdated: This URI [" << ExtendedContact::urlToString(ec->mSipContact->m_url)
			      << "] does not match a tport.";
		}
	}
}

OnRequestBindListener::OnRequestBindListener(ModuleRegistrar* module,
                                             std::shared_ptr<RequestSipEvent> ev,
                                             const sip_from_t* sipuri,
                                             sip_contact_t* contact,
                                             sip_path_t* path)
    : mModule(module), mEv(ev), mSipFrom(nullptr), mContact(nullptr), mPath(nullptr) {
	ev->suspendProcessing();
	su_home_init(&mHome);
	if (contact) mContact = sip_contact_copy(&mHome, contact);
	if (path) mPath = sip_path_copy(&mHome, path);
	if (sipuri) {
		mSipFrom = sip_from_dup(&mHome, sipuri);
	}
}
OnRequestBindListener::~OnRequestBindListener() {
	su_home_deinit(&mHome);
}

void OnRequestBindListener::onContactUpdated(const std::shared_ptr<ExtendedContact>& ec) {
	_onContactUpdated(this->mModule, this->mEv->getIncomingTport().get(), ec);
}

void OnRequestBindListener::onRecordFound(const shared_ptr<Record>& r) {
	const shared_ptr<MsgSip>& ms = mEv->getMsgSip();
	if (r) {
		addEventLogRecordFound(mEv, r, mContact);
		mModule->reply(mEv, 200, "Registration successful", r->getContacts(ms->getHome()));
		if (mContact) {
			string uid = r->extractUniqueId(mContact);
			mModule->getAgent()->getRegistrarDb().publish(
			    Record::Key(mSipFrom->a_url, mModule->getAgent()->getRegistrarDb().useGlobalDomain()), uid);
		}
		/*
		 * Tell SofiaSip to reply to CRLF pings only if
		 * the 'outbound' extension is supported by the client.
		 */
		auto sip = mEv->getMsgSip()->getSip();
		if (sip_has_supported(sip->sip_supported, "outbound")) {
			auto tport = mEv->getIncomingTport();
			SLOGD << "Enable Pong2ping on IncomingTport[" << tport << "]";
			tport_set_params(tport.get(), TPTAG_PONG2PING(1), TAG_END());
		}
	} else {
		LOGE("OnRequestBindListener::onRecordFound(): Record is null");
		mModule->reply(mEv, SIP_500_INTERNAL_SERVER_ERROR);
	}
}
void OnRequestBindListener::onError(const SipStatus& response) {
	LOGE("OnRequestBindListener::onError: reply %s", response.getReason());
	mModule->reply(mEv, response.getCode(), response.getReason());
}

void OnRequestBindListener::onInvalid(const SipStatus& response) {
	LOGE("OnRequestBindListener::onInvalid: reply %s", response.getReason());
	mModule->reply(mEv, response.getCode(), response.getReason());
}

OnResponseBindListener::OnResponseBindListener(ModuleRegistrar* module,
                                               shared_ptr<ResponseSipEvent> ev,
                                               shared_ptr<OutgoingTransaction> tr,
                                               shared_ptr<ResponseContext> ctx)
    : mModule(module), mEv(ev), mTr(tr), mCtx(ctx) {
	ev->suspendProcessing();
}

void OnResponseBindListener::onRecordFound(const shared_ptr<Record>& r) {
	const shared_ptr<MsgSip>& ms = mEv->getMsgSip();

	if (r == nullptr) {
		LOGE("OnResponseBindListener::onRecordFound(): Record is null");
		mCtx->mRequestSipEvent->reply(SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		mEv->terminateProcessing();
		return;
	}

	string uid = r->extractUniqueId(mCtx->mOriginalContacts);
	mModule->getAgent()->getRegistrarDb().publish(Record::Key(mCtx->mRequestSipEvent->getSip()->sip_from->a_url,
	                                                          mModule->getAgent()->getRegistrarDb().useGlobalDomain()),
	                                              uid);

	sip_contact_t* dbContacts = r->getContacts(ms->getHome());

	// Replace received contacts by our ones
	auto& reMs = mEv->getMsgSip();
	msg_header_remove_all(reMs->getMsg(), (msg_pub_t*)reMs->getSip(), (msg_header_t*)reMs->getSip()->sip_contact);
	msg_header_insert(reMs->getMsg(), (msg_pub_t*)reMs->getSip(), (msg_header_t*)dbContacts);

	mModule->removeInternalParams(reMs->getSip()->sip_contact);

	addEventLogRecordFound(mEv, r, dbContacts);
	mModule->getAgent()->injectResponseEvent(mEv);
}
void OnResponseBindListener::onError(const SipStatus& response) {
	LOGE("OnResponseBindListener::onError: reply %s", response.getReason());
	mCtx->mRequestSipEvent->reply(response.getCode(), response.getReason(), TAG_END());
	mEv->terminateProcessing();
}

void OnResponseBindListener::onInvalid(const SipStatus& response) {
	LOGE("OnResponseBindListener::onInvalid: reply %s", response.getReason());
	mCtx->mRequestSipEvent->reply(response.getCode(), response.getReason(), TAG_END());
	mEv->terminateProcessing();
}

void OnResponseBindListener::onContactUpdated(const shared_ptr<ExtendedContact>& ec) {
	_onContactUpdated(this->mModule, this->mCtx->mRequestSipEvent->getIncomingTport().get(), ec);
}

OnStaticBindListener::OnStaticBindListener(const url_t* from, const sip_contact_t* ct) {
	mFrom = url_as_string(mHome.home(), from);
	mContact = url_as_string(mHome.home(), ct->m_url);
}
void OnStaticBindListener::onRecordFound([[maybe_unused]] const shared_ptr<Record>& r) {
	LOGD("Static route added for %s: %s", mFrom.c_str(), mContact.c_str());
}
void OnStaticBindListener::onError(const SipStatus&) {
	LOGE("Can't add static route for %s", mFrom.c_str());
}
void OnStaticBindListener::onInvalid(const SipStatus&) {
	LOGE("OnStaticBindListener onInvalid");
}
void OnStaticBindListener::onContactUpdated([[maybe_unused]] const shared_ptr<ExtendedContact>& ec) {
}

FakeFetchListener::FakeFetchListener() {
}

void FakeFetchListener::onRecordFound(const shared_ptr<Record>& r) {
	if (r != nullptr) {
		SLOGD << r;
	} else {
		LOGD("No record found");
	}
}
void FakeFetchListener::onError(const SipStatus&) {
}

void FakeFetchListener::onInvalid(const SipStatus&) {
	LOGD("FakeFetchListener: onInvalid");
}

void FakeFetchListener::onContactUpdated([[maybe_unused]] const shared_ptr<ExtendedContact>& ec) {
}

ResponseContext::ResponseContext(const shared_ptr<RequestSipEvent>& ev, int globalDelta) : mRequestSipEvent{ev} {
	sip_t* sip = ev->getMsgSip()->getSip();
	mOriginalContacts = sip_contact_dup(mRequestSipEvent->getHome(), sip->sip_contact);
	for (sip_contact_t* it = mOriginalContacts; it; it = it->m_next) {
		int cExpire = ExtendedContact::resolveExpire(it->m_expires, globalDelta);
		it->m_expires = su_sprintf(mRequestSipEvent->getHome(), "%d", cExpire);
	}
}

/**
 * Delta from expires header, normalized with custom rules.
 * return -1 on error
 */
static int normalizeMainDelta(const sip_expires_t* expires, const uint min, const uint max) {
	if (!expires) return -1;

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
static bool checkStarUse(const sip_contact_t* contact, int expires) {
	bool starFound = false;
	int count = 0;
	do {
		if (starFound) {
			return false;
		}

		++count;
		const char* scheme = contact->m_url[0].url_scheme;
		if (scheme && '*' == scheme[0]) {
			if (count > 1 || 0 != expires) return false;
			starFound = true;
		}
	} while (nullptr != (contact = contact->m_next));
	return true;
}

// Check an expire is present globally or in contact.
static bool checkHaveExpire(const sip_contact_t* c, int expires) {
	if (expires >= 0) return true; // there exist a global expire
	while (c) {
		if (!c->m_expires || atoi(c->m_expires) < 0) return false;
		c = c->m_next;
	}
	return true;
}

ostream& operator<<(ostream& strm, const sip_contact_t* c) {
	char b[500];
	sip_contact_e(b, sizeof(b) - 1, (msg_header_t const*)c, 0);
	strm << b;
	return strm;
}

static void replyPopulateEventLog(shared_ptr<SipEvent> ev, const sip_t* sip, int code, const char* reason) {
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

static void
staticRoutesRereadTimerfunc([[maybe_unused]] su_root_magic_t* magic, [[maybe_unused]] su_timer_t* t, void* data) {
	ModuleRegistrar* r = (ModuleRegistrar*)data;
	r->readStaticRecords();
}

ModuleRegistrar::ModuleRegistrar(Agent* ag, const ModuleInfoBase* moduleInfo)
    : Module(ag, moduleInfo), mStaticRecordsTimer(nullptr) {
	mStaticRecordsVersion = 0;
	mStats.mCountClear = mModuleConfig->getStatPairPtr("count-clear");
	mStats.mCountBind = mModuleConfig->getStatPairPtr("count-bind");
	mStats.mCountLocalActives = mModuleConfig->getStat("count-local-registered-users");
}

void ModuleRegistrar::declareConfig(GenericStruct& moduleConfig) {
	ConfigItemDescriptor configs[] = {
	    {
	        StringList,
	        "reg-domains",
	        "List of whitespace separated domain names which the registar is in charge of. It can eventually be "
	        "the '*' (wildcard) in order to match any domain name.",
	        "localhost",
	    },
	    {
	        Boolean,
	        "reg-on-response",
	        "Register users based on response obtained from a back-end server. "
	        "This mode is for using flexisip as a front-end server to hold client connections but register"
	        "acceptance is deferred to backend server to which the REGISTER is routed.",
	        "false",
	    },
	    {
	        // Used by registrardb
	        Integer,
	        "max-contacts-by-aor",
	        "Maximum number of registered contacts per address of record.",
	        "12",
	    },
	    {
	        Integer,
	        "max-contacts-per-registration",
	        "Limits the number of authorized \"Contact:\" headers in a REGISTER request. If the number of \"Contact:\" "
	        "headers exceeds this limit, the request is rejected.",
	        "1",
	    },
	    {
	        StringList,
	        "unique-id-parameters",
	        "List of contact URI parameters that can be used to identify a user's device. "
	        "The contact parameters are searched in the order of the list, the first matching parameter is used and "
	        "the others ignored.",
	        "+sip.instance pn-tok line",
	    },
	    {
	        Boolean,
	        "enable-gruu",
	        "When supported by the client, assign a pub-gruu address to the client, returned in the response. ",
	        "true",
	    },
	    {
	        DurationS,
	        "max-expires",
	        "Maximum expire time for a REGISTER.",
	        "86400",
	    },
	    {
	        DurationS,
	        "min-expires",
	        "Minimum expire time for a REGISTER.",
	        "60",
	    },
	    {
	        Integer,
	        "force-expires",
	        "Set a value that will override expire times given by the "
	        "REGISTER requests. A null or negative value disables "
	        "that feature. If it is enabled, max-expires and min-expires "
	        "will not have any effect.",
	        "-1",
	    },
	    {
	        String,
	        "static-records-file",
	        "File containing the static records to add to database on startup. "
	        "Format: one 'sip_uri contact_header' by line. Example:\n"
	        "<sip:contact@domain> <sip:127.0.0.1:5460>,<sip:192.168.0.1:5160>",
	        "",
	    },
	    {
	        DurationS,
	        "static-records-timeout",
	        "Timeout after which the static records file is re-read and the contacts updated.",
	        "600",
	    },
	    {
	        String,
	        "db-implementation",
	        "Implementation used for storing the contact URIs of each address of record. Two backends are available:\n"
	        " - redis : contacts are stored in a Redis database, which allows persistent and shared storage accross "
	        "multiple Flexisip instances.\n"
	        " - internal : contacts are stored in RAM. Of course, if flexisip is restarted, all the contact URIs are "
	        "lost until clients update their registration.\n"
	        "The redis backend is recommended, the internal being more adapted to very small deployments.",
	        "internal",
	    },

	    // Redis config support
	    {
	        String,
	        "redis-server-domain",
	        "Hostname or address of the Redis server. ",
	        "localhost",
	    },
	    {
	        Integer,
	        "redis-server-port",
	        "Port of the Redis server.",
	        "6379",
	    },
	    {
	        String,
	        "redis-auth-user",
	        "ACL username used to authenticate on Redis. Empty to disable. Setting this but not `redis-auth-password` "
	        "is "
	        "a misconfiguration, and will be ignored.",
	        "",
	    },
	    {
	        String,
	        "redis-auth-password",
	        "Authentication password for Redis. Empty to disable. If set but `redis-auth-user` is left unset or empty, "
	        "Flexisip will attempt to register in legacy mode.",
	        "",
	    },
	    {
	        DurationS,
	        "redis-slave-check-period",
	        "When Redis is configured in master-slave, Flexisip will periodically ask which Redis instances are the "
	        "slaves and the master. This is the period at which it will query the server. It will then determine "
	        "whether it is connected to the master, and if not, will terminate the connection and migrate to the "
	        "master.\n"
	        "Note: This requires that all Redis instances have the same password. Otherwise authentication will fail.",
	        "60",
	    },
	    {
	        Boolean,
	        "redis-use-slaves-as-backup",
	        "Tell if Flexisip should try to connect to Redis slaves if master went down. Can be disabled if slaves "
	        "hostname info are on private network for example.",
	        "true",
	    },
	    {
	        String,
	        "service-route",
	        "Sequence of proxies (space-separated) where requests will be redirected through (RFC3608)",
	        "",
	    },
	    {
	        String,
	        "message-expires-param-name",
	        "Name of the custom Contact header parameter which is to indicate the expire "
	        "time for chat message delivery.",
	        "message-expires",
	    },
	    {
	        Integer,
	        "register-expire-randomizer-max",
	        "If not zero, the expire time put in the 200 OK response won't be the one required by the user agent, but "
	        "will be slightly modified by subtracting a random value. The value given by this parameter is the "
	        "maximum percentage of the initial expire that can be subtracted.\n"
	        "If zero, no randomization is applied. Value must be in [0, 100].",
	        "0",
	    },

	    // Deprecated parameters
	    {
	        String,
	        "redis-record-serializer",
	        "Serialize contacts with: [C, protobuf, json, msgpack]",
	        "protobuf",
	    },
	    {
	        DurationMS,
	        "redis-server-timeout",
	        "Timeout of the Redis connection.",
	        "1500",
	    },
	    {
	        String,
	        "name-message-expires",
	        "Name of the custom Contact header parameter which is to indicate the expire "
	        "time for chat message delivery.",
	        "message-expires",
	    },
	    config_item_end};
	moduleConfig.addChildrenValues(configs);

	moduleConfig.get<ConfigString>("redis-record-serializer")
	    ->setDeprecated({
	        "2020-01-28",
	        "2.0.0",
	        "This setting no longer has any effect. It should be removed from the config file.",
	    });

	auto* oldMessageExpiresParamName = moduleConfig.get<ConfigString>("name-message-expires");
	oldMessageExpiresParamName->setDeprecated({
	    "2020-03-25",
	    "2.0.0",
	    "This parameter has been renamed into 'message-expires-param-name'",
	});
	moduleConfig.get<ConfigString>("message-expires-param-name")->setFallback(*oldMessageExpiresParamName);

	moduleConfig.get<ConfigDuration<chrono::milliseconds>>("redis-server-timeout")
	    ->setDeprecated({
	        "2024-03-01",
	        "2.4.0",
	        "While this parameter currently has no effect, it is not considered officially deprecated. It remains "
	        "unused for now, but may be utilized in future updates.",
	    });

	moduleConfig.createStatPair("count-clear", "Number of cleared registrations.");
	moduleConfig.createStatPair("count-bind", "Number of registers.");
	moduleConfig.createStat("count-local-registered-users",
	                        "Number of users currently registered through this server.");
}

void ModuleRegistrar::onLoad(const GenericStruct* mc) {
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
	if (forcedExpires <= 0) {
		mMaxExpires =
		    chrono::duration_cast<chrono::seconds>(mc->get<ConfigDuration<chrono::seconds>>("max-expires")->read())
		        .count();
		mMinExpires =
		    chrono::duration_cast<chrono::seconds>(mc->get<ConfigDuration<chrono::seconds>>("min-expires")->read())
		        .count();
		if (mMaxExpires < mMinExpires) LOGF("Registrar 'max-expires' must be equal to or greater than 'min-expires'");
	} else {
		mMaxExpires = forcedExpires;
		mMinExpires = forcedExpires;
	}

	mStaticRecordsFile = mc->get<ConfigString>("static-records-file")->read();
	mStaticRecordsTimeout = chrono::duration_cast<chrono::seconds>(
	                            mc->get<ConfigDuration<chrono::seconds>>("static-records-timeout")->read())
	                            .count();

	mExpireRandomizer = mc->get<ConfigInt>("register-expire-randomizer-max")->read();
	if (mExpireRandomizer < 0 || mExpireRandomizer > 100) {
		LOGF("'register-expire-randomizer-max' value (%i) must be in [0,100]", mExpireRandomizer);
	}
	const auto* maxContactsPerRegistration = mc->get<ConfigInt>("max-contacts-per-registration");
	mMaxContactsPerRegistration = maxContactsPerRegistration->read();
	if (mMaxContactsPerRegistration <= 0)
		throw FlexisipException{maxContactsPerRegistration->getCompleteName() + " must be strictly positive"};

	if (!mStaticRecordsFile.empty()) {
		readStaticRecords(); // read static records from configuration file
		mStaticRecordsTimer = mAgent->createTimer(mStaticRecordsTimeout * 1000, &staticRoutesRereadTimerfunc, this);
	}
	mAllowDomainRegistrations = getAgent()
	                                ->getConfigManager()
	                                .getRoot()
	                                ->get<GenericStruct>("inter-domain-connections")
	                                ->get<ConfigBoolean>("accept-domain-registrations")
	                                ->read();
	mAssumeUniqueDomains = getAgent()
	                           ->getConfigManager()
	                           .getRoot()
	                           ->get<GenericStruct>("inter-domain-connections")
	                           ->get<ConfigBoolean>("assume-unique-domains")
	                           ->read();
	mUseGlobalDomain = getAgent()
	                       ->getConfigManager()
	                       .getRoot()
	                       ->get<GenericStruct>("module::Router")
	                       ->get<ConfigBoolean>("use-global-domain")
	                       ->read();
	mParamsToRemove = getAgent()
	                      ->getConfigManager()
	                      .getRoot()
	                      ->get<GenericStruct>("module::Forward")
	                      ->get<ConfigStringList>("params-to-remove")
	                      ->read();

	mSignalHandler = std::make_unique<signal_handling::SofiaDrivenSignalHandler>(
	    getAgent()->getRoot()->getCPtr(), std::vector<int>{SIGUSR1, SIGUSR2},
	    // SAFETY: Capturing `this` is safe because we keep a handle to the Handler.
	    [this](auto signum) {
		    if (signum == SIGUSR1) {
			    LOGI("Received signal triggering static records file re-read");
			    readStaticRecords();
		    } else if (signum == SIGUSR2) {
			    LOGI("Received signal triggering fake fetch");
			    auto listener = make_shared<FakeFetchListener>();
			    mAgent->getRegistrarDb().fetch(SipUri("sip:contact@domain"), listener, false);
		    }
	    });
}

void ModuleRegistrar::onUnload() {
	if (mStaticRecordsTimer) {
		su_timer_destroy(mStaticRecordsTimer);
	}
}

void ModuleRegistrar::idle() {
	chrono::steady_clock::time_point start, stop;
	start = chrono::steady_clock::now();
	updateLocalRegExpire();
	stop = chrono::steady_clock::now();
	unsigned long durationMs =
	    (unsigned long)std::chrono::duration_cast<std::chrono::milliseconds>((stop) - (start)).count();
	if (durationMs >= 1000) {
		LOGW("ModuleRegistrar::idle() (registrar expired aor cleanup) took %lu ms", durationMs);
	}
}

std::shared_ptr<ResponseContext> ModuleRegistrar::createResponseContext(const std::shared_ptr<RequestSipEvent>& ev,
                                                                        int globalDelta) {
	auto otr = ev->createOutgoingTransaction();
	auto context = make_shared<ResponseContext>(ev, globalDelta);
	otr->setProperty(getModuleName(), context);
	return context;
}

void ModuleRegistrar::deleteResponseContext(const std::shared_ptr<ResponseContext>& ctx) {
	auto otr = ctx->mRequestSipEvent->getOutgoingTransaction();
	if (otr) otr->removeProperty(getModuleName());
}

void ModuleRegistrar::updateLocalRegExpire() {
	mAgent->getRegistrarDb().mLocalRegExpire.removeExpiredBefore(getCurrentTime());
	mStats.mCountLocalActives->set(mAgent->getRegistrarDb().mLocalRegExpire.countActives());
}

bool ModuleRegistrar::isManagedDomain(const url_t* url) {
	return ModuleToolbox::isManagedDomain(getAgent(), mDomains, url);
}

void ModuleRegistrar::removeInternalParams(sip_contact_t* ct) {
	for (sip_contact_t* contact = ct; contact != nullptr; contact = contact->m_next) {
		if (contact) {
			if (url_has_param(contact->m_url, "fs-conn-id")) {
				contact->m_url->url_params = url_strip_param_string((char*)contact->m_url->url_params, "fs-conn-id");
			}
			const char* pub_gruu_value = msg_header_find_param((msg_common_t*)contact, "pub-gruu");
			if (pub_gruu_value && pub_gruu_value[0] == '\0') {
				/* Remove empty pub-gruu parameter, which is set internally
				 * for compatibility with previous gruu implementation.*/
				msg_header_remove_param((msg_common_t*)contact, "pub-gruu");
			}
		}
	}
}

int ModuleRegistrar::numberOfContactHeaders(const sip_contact_t* rootHeader) {
	int count = 0;
	for (const auto* header = rootHeader; header != nullptr; header = header->m_next) {
		++count;
	}
	return count;
}

void ModuleRegistrar::reply(shared_ptr<RequestSipEvent>& ev,
                            int code,
                            const char* reason,
                            const sip_contact_t* contacts) {
	sip_contact_t* modified_contacts = nullptr;
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	sip_t* sip = ms->getSip();
	int expire = sip->sip_expires ? normalizeMainDelta(sip->sip_expires, mMinExpires, mMaxExpires) : 0;
	const char* supported = "path, outbound"; // indicate that the registrar supports these extensions

	replyPopulateEventLog(ev, sip, code, reason);

	if (!mServiceRoute.empty()) {
		LOGD("Setting service route to %s", mServiceRoute.c_str());
	}

	if (contacts) {
		modified_contacts = sip_contact_dup(ev->getHome(), contacts);
	}
	// This ensures not all REGISTERs arrive at the same time on the flexisip
	if (sip->sip_request->rq_method == sip_method_register && code == 200 && mExpireRandomizer > 0 && expire > 0) {
		expire -= (int)(expire * su_randint(0, mExpireRandomizer) / 100.0);
		if (contacts) {
			su_home_t* home = ev->getHome();
			msg_header_replace_param(home, (msg_common_t*)modified_contacts, su_sprintf(home, "expires=%i", expire));
		}
	}
	string expire_str = std::to_string(expire);

	removeInternalParams(modified_contacts);
	if (modified_contacts && !mServiceRoute.empty()) {
		if (expire > 0) {
			ev->reply(code, reason, SIPTAG_CONTACT(modified_contacts), SIPTAG_SERVICE_ROUTE_STR(mServiceRoute.c_str()),
			          SIPTAG_SERVER_STR(getAgent()->getServerString()), SIPTAG_EXPIRES_STR(expire_str.c_str()),
			          SIPTAG_SUPPORTED_STR(supported), TAG_END());
		} else {
			ev->reply(code, reason, SIPTAG_CONTACT(modified_contacts), SIPTAG_SERVICE_ROUTE_STR(mServiceRoute.c_str()),
			          SIPTAG_SERVER_STR(getAgent()->getServerString()), SIPTAG_SUPPORTED_STR(supported), TAG_END());
		}
	} else if (modified_contacts) {
		if (expire > 0) {
			ev->reply(code, reason, SIPTAG_CONTACT(modified_contacts), SIPTAG_SERVER_STR(getAgent()->getServerString()),
			          SIPTAG_EXPIRES_STR(expire_str.c_str()), SIPTAG_SUPPORTED_STR(supported), TAG_END());
		} else {
			ev->reply(code, reason, SIPTAG_CONTACT(modified_contacts), SIPTAG_SERVER_STR(getAgent()->getServerString()),
			          SIPTAG_SUPPORTED_STR(supported), TAG_END());
		}
	} else if (!mServiceRoute.empty()) {
		if (expire > 0) {
			ev->reply(code, reason, SIPTAG_SERVICE_ROUTE_STR(mServiceRoute.c_str()),
			          SIPTAG_SERVER_STR(getAgent()->getServerString()), SIPTAG_EXPIRES_STR(expire_str.c_str()),
			          SIPTAG_SUPPORTED_STR(supported), TAG_END());
		} else {
			ev->reply(code, reason, SIPTAG_SERVICE_ROUTE_STR(mServiceRoute.c_str()),
			          SIPTAG_SERVER_STR(getAgent()->getServerString()), SIPTAG_SUPPORTED_STR(supported), TAG_END());
		}
	} else {
		if (expire > 0) {
			ev->reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()),
			          SIPTAG_EXPIRES_STR(expire_str.c_str()), SIPTAG_SUPPORTED_STR(supported), TAG_END());
		} else {
			ev->reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), SIPTAG_SUPPORTED_STR(supported),
			          TAG_END());
		}
	}
}

inline static bool containsNonZeroExpire(const sip_expires_t* main, const sip_contact_t* c) {
	bool nonZeroMain = main && main->ex_delta > 0;
	while (c != nullptr) {
		if (c->m_expires) {
			if (atoi(c->m_expires) > 0) return true;
		} else if (nonZeroMain) {
			return true;
		}
		c = c->m_next;
	}
	return false;
}

template <typename SipEventT, typename ListenerT>
void ModuleRegistrar::processUpdateRequest(shared_ptr<SipEventT>& ev, const sip_t* sip) {
	const sip_expires_t* expires = sip->sip_expires;
	const int maindelta = normalizeMainDelta(expires, mMinExpires, mMaxExpires);
	if ('*' == sip->sip_contact->m_url[0].url_scheme[0]) {
		auto listener = make_shared<ListenerT>(this, ev);
		mStats.mCountClear->incrStart();
		LOGD("Clearing bindings");
		listener->addStatCounter(mStats.mCountClear->finish);
		mAgent->getRegistrarDb().clear(sip, listener);
		return;
	} else {
		auto listener = make_shared<ListenerT>(this, ev, sip->sip_from, sip->sip_contact);
		mStats.mCountBind->incrStart();
		LOGD("Updating binding");
		listener->addStatCounter(mStats.mCountBind->finish);
		mAgent->getRegistrarDb().bind(sip, maindelta, false, 0, listener);
		return;
	}
}

void ModuleRegistrar::onRequest(shared_ptr<RequestSipEvent>& ev) {
	const auto& ms = ev->getMsgSip();
	auto* sip = ms->getSip();
	if (sip->sip_request->rq_method != sip_method_register) return;

	// Check that From-URI is a SIP URI
	SipUri sipurl{};
	try {
		sipurl = SipUri(sip->sip_from->a_url);
	} catch (const sofiasip::InvalidUrlError& e) {
		SLOGE << "Invalid 'From' URI [" << e.getUrl() << "]: " << e.getReason();
		ev->reply(400, "Bad request", TAG_END());
		return;
	}

	// From managed domains
	if (!isManagedDomain(sipurl.get())) return;

	// Handle fetching
	if (sip->sip_contact == nullptr) {
		LOGD("No sip contact, it is a fetch only request for %s.", sipurl.str().c_str());
		auto listener = make_shared<OnRequestBindListener>(this, ev);
		mAgent->getRegistrarDb().fetch(sipurl, listener);
		return;
	}

	// Reject malformed registrations
	const auto* expires = sip->sip_expires;
	const auto maindelta = normalizeMainDelta(expires, mMinExpires, mMaxExpires);
	if (!checkHaveExpire(sip->sip_contact, maindelta)) {
		SLOGD << "No global or local expire found in at least one contact";
		reply(ev, 400, "Invalid request");
		return;
	}
	for (auto contact = sip->sip_contact; contact != nullptr; contact = contact->m_next) {
		if (!isValidSipUri(contact->m_url)) {
			reply(ev, 400, "Invalid contact");
			return;
		}
	}
	if (!checkStarUse(sip->sip_contact, maindelta)) {
		LOGD("The star rules are not respected.");
		reply(ev, 400, "Invalid request");
		return;
	}
	if (numberOfContactHeaders(sip->sip_contact) > mMaxContactsPerRegistration) {
		reply(ev, 403, "Too many contacts in REGISTER");
		return;
	}

	// Use path as a contact route in all cases
	// Preferred Route is only set if cluster mode is enabled
	if (!getAgent()->getPreferredRoute().empty()) {
		sip_path_t* path =
		    sip_path_format(ms->getHome(), "<%s>", getAgent()->getPreferredRoute().c_str()); // format a Path
		msg_t* msg = ev->getMsgSip()->getMsg();
		if (!ModuleToolbox::prependNewRoutable(msg, sip, sip->sip_path, path)) {
			SLOGD << "Identical path already existing: " << getAgent()->getPreferredRoute();
		}
	} else {
		mAgent->getNatTraversalStrategy()->addPathOnRegister(ev, ev->getIncomingTport().get(), nullptr);
	}

	/* Initialize a connection ID, so that registration can be matched with the tport,
	   in order to later identify aborted connections during subsequent registrations. */
	{
		ostringstream os;
		uintptr_t connId = (tport_get_user_data(ev->getIncomingTport().get()))
		                       ? reinterpret_cast<uintptr_t>(tport_get_user_data(ev->getIncomingTport().get()))
		                       : static_cast<uintptr_t>(su_random64());
		os << "fs-conn-id=" << hex << connId;
		url_param_add(ms->getHome(), sip->sip_contact->m_url, os.str().c_str());
		tport_set_user_data(ev->getIncomingTport().get(), reinterpret_cast<void*>(connId));
	}

	// Domain registration case, does nothing for the moment
	if (sipurl.getUser().empty() && !mAllowDomainRegistrations) {
		LOGE("Not accepting domain registration");
		SLOGUE << "Not accepting domain registration:  " << sipurl;
		reply(ev, 403, "Domain registration forbidden", nullptr);
		return;
	}

	/* Evaluate whether the REGISTER needs to be answered and processed directly, or forwarded to an upstream server
	 * which is the case when reg-on-response is enabled, but with a few exceptions listed below. */
	bool updateOnResponse = mUpdateOnResponse;
	if (updateOnResponse) {
		if (sipurl.getUser().empty()) {
			// This is a domain registration, it has to be answered directly.
			updateOnResponse = false;
		} else if (mAllowDomainRegistrations) {
			/* Domain registrations are enabled. In this case we evaluate whether the
			 * relay-reg-to-domains and the relay-reg-to-domains-regex properties allow this REGISTER
			 * to be sent upstream. */
			updateOnResponse = getAgent()->getDRM()->haveToRelayRegToDomain(sipurl.getHost());
		}
	}
	if (!updateOnResponse) {
		// Main case: the module directly answers to the REGISTER.
		if ('*' == sip->sip_contact->m_url[0].url_scheme[0]) {
			auto listener = make_shared<OnRequestBindListener>(this, ev);
			mStats.mCountClear->incrStart();
			LOGD("Clearing bindings");
			listener->addStatCounter(mStats.mCountClear->finish);
			mAgent->getRegistrarDb().clear(*ms, listener);
			return;
		} else {
			if (sipurl.getUser().empty() && mAssumeUniqueDomains) {
				/*first clear to make sure that there is only one record*/
				mAgent->getRegistrarDb().clear(*ms, make_shared<FakeFetchListener>());
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
			parameter.isAliasFunction = [this](const url_t* ct) -> bool { return isManagedDomain(ct); };
			mAgent->getRegistrarDb().bind(*ms, parameter, listener);
			return;
		}
	} else {
		/* Case where the module let the REGISTER being forwared upstream.
		 * The final response is generated upon receiving the response from the upstream server
		 * in onResponse(). */
		ev->createIncomingTransaction();
		ev->reply(SIP_100_TRYING, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());

		auto context = createResponseContext(ev, maindelta);

		su_home_t* home = ev->getMsgSip()->getHome();
		url_t* gruuAddress;
		if (mAgent->getRegistrarDb().gruuEnabled() &&
		    (gruuAddress = mAgent->getRegistrarDb().synthesizePubGruu(home, *ev->getMsgSip()))) {
			/* A gruu address can be assigned to this contact. Replace the contact with the GRUU address we are going to
			 * create for the contact.*/
			msg_header_remove_all(ev->getMsgSip()->getMsg(), (msg_pub_t*)ev->getSip(),
			                      (msg_header_t*)ev->getSip()->sip_contact);
			msg_header_insert(ev->getMsgSip()->getMsg(), (msg_pub_t*)ev->getSip(),
			                  (msg_header_t*)sip_contact_create(home, (url_string_t*)gruuAddress, NULL));
		} else {
			// Legacy code: just cleaner contacts
			ModuleToolbox::removeParamsFromContacts(home, sip->sip_contact, mUniqueIdParams);
			ModuleToolbox::removeParamsFromContacts(home, sip->sip_contact, mParamsToRemove);
			SLOGD << "Removed instance and push params: \n" << sip->sip_contact;
		}
		// Let the modified initial event flow (will not be forked).
	}
}

void ModuleRegistrar::onResponse(shared_ptr<ResponseSipEvent>& ev) {
	if (!mUpdateOnResponse) return;
	const shared_ptr<MsgSip>& reMs = ev->getMsgSip();
	sip_t* reSip = reMs->getSip();

	// Only handle response to registers
	if (reSip->sip_cseq->cs_method != sip_method_register) return;
	// Handle db update on response
	const url_t* reSipurl = reSip->sip_from->a_url;
	if (!reSipurl->url_host || !isManagedDomain(reSipurl)) return;

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
		const sip_expires_t* expires;
		shared_ptr<MsgSip> request = transaction->getRequestMsg();
		if (request) {
			expires = request->getSip()->sip_expires;
		} else {
			expires = reSip->sip_expires;
		}
		const int maindelta = normalizeMainDelta(expires, mMinExpires, mMaxExpires);
		auto listener = make_shared<OnResponseBindListener>(this, ev, transaction, context);

		if ('*' == request->getSip()->sip_contact->m_url[0].url_scheme[0]) {
			mStats.mCountClear->incrStart();
			LOGD("Clearing bindings");
			listener->addStatCounter(mStats.mCountClear->finish);
			mAgent->getRegistrarDb().clear(*request, listener);
		} else {
			BindingParameters parameter;
			mStats.mCountBind->incrStart();
			LOGD("Updating binding");
			parameter.alias = false;
			parameter.globalExpire = maindelta;
			parameter.version = 0;
			parameter.isAliasFunction = [this](const url_t* ct) -> bool { return isManagedDomain(ct); };
			listener->addStatCounter(mStats.mCountBind->finish);

			/* Before submiting the bind() request to the RegistrarDb, restore the Contact header as it was found in the
			 * original request received from the client.*/
			msg_header_remove_all(request->getMsg(), (msg_pub_t*)request->getSip(),
			                      (msg_header_t*)request->getSip()->sip_contact);
			msg_header_insert(request->getMsg(), (msg_pub_t*)request->getSip(),
			                  (msg_header_t*)context->mOriginalContacts);

			mAgent->getRegistrarDb().bind(*request, parameter, listener);
		}
	}
	if (reSip->sip_status->st_status >= 200) {
		/*for all final responses, drop the context anyway*/
		deleteResponseContext(context);
	}
}

void ModuleRegistrar::readStaticRecords() {
	int linenum = 0;

	if (mStaticRecordsFile.empty()) {
		SLOGW << "No static-records-file configured. Nothing to read.";
		return;
	}
	LOGD("Reading static records file");

	sofiasip::Home home;

	ifstream file(mStaticRecordsFile);
	if (!file.is_open()) {
		LOGE("Can't open file %s", mStaticRecordsFile.c_str());
		return;
	}

	SipUri path{getAgent()->getPreferredRoute()};
	mStaticRecordsVersion++;

	const regex isCommentOrEmptyRe(R"regex(^\s*(#.*)?$)regex");
	const regex isRecordRe(R"regex(^\s*([[:print:]]+)\s+([[:print:]]+)\s*$)regex");
	while (file.good() && !file.eof()) {
		string line;
		string from;
		string contact_header;
		smatch m;

		getline(file, line), ++linenum;

		try {
			if (regex_match(line, m, isCommentOrEmptyRe)) continue;

			else if (regex_match(line, m, isRecordRe)) {
				from = m[1];
				contact_header = m[2];
			} else {
				throw runtime_error("invalid line syntax");
			}

			// Create
			sip_contact_t* url = sip_contact_make(home.home(), from.c_str());
			sip_contact_t* contact = sip_contact_make(home.home(), contact_header.c_str());
			int expire = mStaticRecordsTimeout + 5; // 5s to avoid race conditions

			if (!url || !contact) {
				throw runtime_error("one URI is invalid");
			}

			SipUri fromUri;
			try {
				fromUri = SipUri(url->m_url);
			} catch (const sofiasip::InvalidUrlError& e) {
				ostringstream os;
				os << "'" << e.getUrl() << "' isn't a valid SIP-URI: " << e.getReason();
				throw runtime_error(os.str());
			}

			{ // Delete existing record
				class ClearListener : public ContactUpdateListener {
				public:
					ClearListener(const std::string& uri) : mUri(uri) {
					}

					void onRecordFound([[maybe_unused]] const shared_ptr<Record>& r) override {
						SLOGD << "Cleared record " << mUri;
					}
					void onError(const SipStatus&) override {
						SLOGE << "Error: cannot clear record " << mUri;
					}
					void onInvalid(const SipStatus&) override {
						SLOGE << "Invalid: cannot clear record " << mUri;
					}
					void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
						SLOGE << "Unexpected call to " << __FUNCTION__ << " for record " << mUri;
					}

				private:
					std::string mUri;
				};

				mAgent->getRegistrarDb().clear(fromUri, "static-record-v"s + to_string(su_random()),
				                               std::make_shared<ClearListener>(fromUri.str()));
			}

			while (contact) {
				BindingParameters parameter;
				shared_ptr<OnStaticBindListener> listener;
				string fakeCallId = "static-record-v" + to_string(su_random());
				bool alias = isManagedDomain(contact->m_url);
				sip_contact_t* sipContact = sip_contact_dup(home.home(), contact);

				sipContact->m_next = nullptr;
				listener = make_shared<OnStaticBindListener>(url->m_url, contact);

				parameter.callId = fakeCallId;
				parameter.path.add(path);
				parameter.globalExpire = expire;
				parameter.alias = alias;
				parameter.version = mStaticRecordsVersion;

				mAgent->getRegistrarDb().bind(fromUri, sipContact, parameter, listener);
				contact = contact->m_next;
			}

		} catch (const runtime_error& e) {
			SLOGW << "error while reading the static record file [" << mStaticRecordsFile << ":" << linenum << endl
			      << "\t`" << line << "`: " << e.what();
		}
	}
}

ModuleInfo<ModuleRegistrar> ModuleRegistrar::sInfo(
    "Registrar",
    "The Registrar module handles REGISTER requests for domains it is in charge of. It stores the address of record "
    "(AOR) in order to allow routing requests intended to the client who registered. REGISTER requests for other "
    "domains are simply ignored and transferred to the next module.",
    {"Presence"},
    ModuleInfoBase::ModuleOid::Registrar,
    declareConfig);
